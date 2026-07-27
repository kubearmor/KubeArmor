// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// Package procsocket resolves (PID, FD) pairs to network socket addresses
// by parsing the process-namespace-scoped /proc/<pid>/net/tcp[6] files.
//
// Design rationale:
//   - We use /proc/<pid>/net/tcp (process-namespace view) rather than
//     /proc/net/tcp (global). The per-process file only lists sockets
//     in the process's network namespace — far fewer entries, faster scan.
//     This is the same approach used by Coroot's node-agent.
//   - Results are cached keyed by (pid, fd) with a 5-second TTL, so
//     keep-alive HTTPS connections pay the /proc parsing cost only once.
//   - We resolve the FD to a socket inode via /proc/<pid>/fd/<fd>, then
//     search /proc/<pid>/net/tcp[6] for the matching inode.
package procsocket

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cacheTTL     = 5 * time.Second
	cacheMaxSize = 4096
)

// SocketAddr holds the resolved socket addresses for a (PID, FD) pair.
type SocketAddr struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Family  uint32 // 2=AF_INET, 10=AF_INET6
}

type cacheEntry struct {
	addr   SocketAddr
	expiry time.Time
}

type cacheKey struct {
	pid uint32
	fd  uint32
}

// Resolver resolves (PID, FD) → SocketAddr using /proc.
type Resolver struct {
	mu    sync.Mutex
	cache map[cacheKey]cacheEntry
	stop  chan struct{}
}

// New creates a Resolver. The ctx controls the lifecycle of the background
// cache eviction goroutine; cancel it (or use context.Background() and call
// Stop()) to release resources.
func New(ctx context.Context) *Resolver {
	r := &Resolver{
		cache: make(map[cacheKey]cacheEntry, 256),
		stop:  make(chan struct{}),
	}
	go r.gcLoop(ctx)
	return r
}

// Stop shuts down the background GC goroutine.
func (r *Resolver) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
}

// gcLoop periodically evicts expired cache entries.
func (r *Resolver) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.evictExpired()
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		}
	}
}

// evictExpired removes all expired entries from the cache.
func (r *Resolver) evictExpired() {
	now := time.Now()
	r.mu.Lock()
	for k, v := range r.cache {
		if now.After(v.expiry) {
			delete(r.cache, k)
		}
	}
	r.mu.Unlock()
}

// Resolve returns the socket addresses for the given (pid, fd) pair.
// Returns nil if the socket cannot be resolved.
func (r *Resolver) Resolve(pid, fd uint32) *SocketAddr {
	key := cacheKey{pid: pid, fd: fd}

	r.mu.Lock()
	if entry, ok := r.cache[key]; ok {
		if time.Now().Before(entry.expiry) {
			r.mu.Unlock()
			addr := entry.addr
			return &addr
		}
		delete(r.cache, key)
	}
	r.mu.Unlock()

	addr := r.resolve(pid, fd)
	if addr == nil {
		return nil
	}

	r.mu.Lock()
	r.cache[key] = cacheEntry{addr: *addr, expiry: time.Now().Add(cacheTTL)}
	r.mu.Unlock()

	return addr
}

// Invalidate removes the cached entry for (pid, fd).
func (r *Resolver) Invalidate(pid, fd uint32) {
	r.mu.Lock()
	delete(r.cache, cacheKey{pid: pid, fd: fd})
	r.mu.Unlock()
}

// resolve does the actual /proc lookup.
func (r *Resolver) resolve(pid, fd uint32) *SocketAddr {
	inode, err := socketInode(pid, fd)
	if err != nil || inode == 0 {
		return nil
	}

	if addr := searchNetFile(pid, "tcp", inode); addr != nil {
		return addr
	}
	if addr := searchNetFile(pid, "tcp6", inode); addr != nil {
		return addr
	}
	return nil
}

// socketInode returns the socket inode from /proc/<pid>/fd/<fd>.
// The symlink target looks like "socket:[1234567]".
func socketInode(pid, fd uint32) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(path)
	if err != nil {
		return 0, err
	}
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || target[len(target)-1] != ']' {
		return 0, fmt.Errorf("not a socket: %s", target)
	}
	inodeStr := target[len(prefix) : len(target)-1]
	inode, err := strconv.ParseUint(inodeStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse inode %q: %w", inodeStr, err)
	}
	return inode, nil
}

// searchNetFile parses /proc/<pid>/net/<proto> looking for the given socket
// inode. Returns the resolved SocketAddr if found.
//
// /proc/<pid>/net/tcp line format (fields separated by whitespace):
//
//	sl  local_address rem_address  st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode
//	0:  0100007F:1F40 00000000:0000 0A 00000000:00000000 ...  0      12345
//
// Field indices (0-based) after splitting by whitespace:
// 0=sl, 1=local_addr, 2=rem_addr, 3=st, 4=tx_queue:rx_queue (ONE token),
// 5=tr:tm->when (ONE token), 6=retrnsmt, 7=uid, 8=timeout, 9=inode.
// Note: tx_queue:rx_queue is a SINGLE whitespace token, not two — so inode
// is at index 9, not 10.
// Addresses: IPv4 = 8-char little-endian hex; IPv6 = 32-char (4×8 LE u32s).
// Ports: big-endian hex u16 after the ':' in the address field.
func searchNetFile(pid uint32, proto string, inode uint64) *SocketAddr {
	path := fmt.Sprintf("/proc/%d/net/%s", pid, proto)
	f, err := os.Open(path) // #nosec G304 — validated PID integer
	if err != nil {
		return nil
	}
	defer f.Close() // #nosec G307

	isIPv6 := proto == "tcp6"
	family := uint32(2) // AF_INET
	if isIPv6 {
		family = 10 // AF_INET6
	}

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() { // skip header
		return nil
	}

	inodeStr := strconv.FormatUint(inode, 10)

	for scanner.Scan() {
		line := scanner.Text()
		// Fast pre-check before splitting.
		if !strings.Contains(line, inodeStr) {
			continue
		}

		fields := strings.Fields(line)
		// Inode is at field index 9; need at least 10 fields (indices 0-9).
		if len(fields) < 10 {
			continue
		}
		if fields[9] != inodeStr {
			continue
		}

		localIP, localPort, err := parseHexAddr(fields[1], isIPv6)
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseHexAddr(fields[2], isIPv6)
		if err != nil {
			continue
		}

		return &SocketAddr{
			SrcIP:   localIP,
			DstIP:   remoteIP,
			SrcPort: localPort,
			DstPort: remotePort,
			Family:  family,
		}
	}

	return nil
}

// parseHexAddr parses a /proc/net/tcp[6] address field "XXXXXXXX:PPPP".
// IPv4: 8-char little-endian hex u32. IPv6: 32-char (4 × 8-char LE u32s).
// Port: big-endian hex u16.
func parseHexAddr(field string, isIPv6 bool) (net.IP, uint16, error) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid addr field: %q", field)
	}
	portRaw, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("parse port %q: %w", parts[1], err)
	}
	port := uint16(portRaw)

	var ip net.IP
	if !isIPv6 {
		if len(parts[0]) != 8 {
			return nil, 0, fmt.Errorf("ipv4 addr wrong len: %q", parts[0])
		}
		b, err := hex.DecodeString(parts[0])
		if err != nil {
			return nil, 0, err
		}
		// Little-endian stored → reverse to network byte order.
		ip = net.IP{b[3], b[2], b[1], b[0]}
	} else {
		if len(parts[0]) != 32 {
			return nil, 0, fmt.Errorf("ipv6 addr wrong len: %q", parts[0])
		}
		raw := make([]byte, 16)
		for i := 0; i < 4; i++ {
			chunk := parts[0][i*8 : i*8+8]
			b, err := hex.DecodeString(chunk)
			if err != nil {
				return nil, 0, err
			}
			// Each u32 stored little-endian; reverse each 4-byte block.
			raw[i*4+0] = b[3]
			raw[i*4+1] = b[2]
			raw[i*4+2] = b[1]
			raw[i*4+3] = b[0]
		}
		ip = net.IP(raw)
	}

	return ip, port, nil
}

// IPToUint32 converts a 4-byte net.IP to a little-endian uint32 matching the
// BPF ks_tls_chunk SrcIP4/DstIP4 field encoding.
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip4)
}
