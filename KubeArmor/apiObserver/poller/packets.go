// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package poller

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// pktChunk is the Go-side mirror of struct ka_pkt from packet_sniffer.h.
// Must match the BPF layout byte-for-byte (little-endian, no padding surprises).
//
// Layout:
//
//	offset  0: u64 timestamp
//	offset  8: u64 cgroup_id
//	offset 16: u64 id          (monotonic packet ID)
//	offset 24: u32 len         (bytes in buf[] for this chunk)
//	offset 28: u32 tot_len     (total uncompressed packet length)
//	offset 32: u32 counter     (remaining bytes)
//	offset 36: u16 num         (chunk sequence number, 0-based)
//	offset 38: u16 last        (1 if final chunk)
//	offset 40: u16 ip_hdr_type (ETH_P_IP or ETH_P_IPV6)
//	offset 42: u8  direction   (PKT_DIR_RECEIVED=0, PKT_DIR_SENT=1)
//	offset 43: u8  _pad
//	offset 44: u8  buf[4080]
//
// pktChunkBufLen is the payload buffer size per chunk (must match PKT_PART_LEN in BPF).
// pktChunkHdrSize is the sum of all header fields in struct ka_pkt (before buf[]).
// pktChunkMinSize is the minimum valid record size from the perf buffer.
// NOTE: sizeof(struct ka_pkt) in C is 4128 (4124 raw + 4 trailing alignment padding to
// satisfy 8-byte alignment from the leading __u64 fields). The BPF program emits
// sizeof(struct ka_pkt) = 4128 bytes per record. We accept any size >= pktChunkMinSize
// so that both the exact C size (4128) and any future changes are handled gracefully.
const (
	pktChunkBufLen  = 4080
	pktChunkHdrSize = 44                               // 3×u64 + 3×u32 + 3×u16 + 2×u8 = 44 bytes
	pktChunkMinSize = pktChunkHdrSize + pktChunkBufLen // 4124 bytes (raw)
	pktChunkBPFSize = 4128                             // actual sizeof(struct ka_pkt) in C (padded to 8-byte alignment)
)

type pktChunk struct {
	Timestamp uint64
	CgroupID  uint64
	ID        uint64
	Len       uint32
	TotLen    uint32
	Counter   uint32
	Num       uint16
	Last      uint16
	IPHdrType uint16
	Direction uint8
	_pad      uint8 //nolint:structcheck
	Buf       [pktChunkBufLen]uint8
}

// RawPacket is a fully reassembled network packet delivered to the consumer.
type RawPacket struct {
	Timestamp time.Time
	CgroupID  uint64
	Direction uint8  // PKT_DIR_RECEIVED=0, PKT_DIR_SENT=1
	IPHdrType uint16 // ETH_P_IP=0x0800, ETH_P_IPV6=0x86DD
	Data      []byte // raw IP packet bytes (no ethernet framing)
}

// IsTCPSyn returns true if the TCP SYN flag is set in this packet.
// Used to detect new TCP connections so stream state can be reset on port reuse.
// Reads the TCP flags byte directly from the raw IP packet bytes.
func (p *RawPacket) IsTCPSyn() bool {
	const tcpSYN = 0x02
	data := p.Data
	var tcpStart int
	switch p.IPHdrType {
	case 0x0800: // IPv4
		if len(data) < 20 {
			return false
		}
		tcpStart = int(data[0]&0x0f) * 4 // IHL * 4
	case 0x86DD: // IPv6
		tcpStart = 40 // fixed IPv6 header size
	default:
		return false
	}
	// TCP flags byte is at tcpStart+13.
	if len(data) < tcpStart+14 {
		return false
	}
	return data[tcpStart+13]&tcpSYN != 0
}

// pktBuffer holds partially assembled multi-chunk packets.
type pktBuffer struct {
	id        uint64
	num       uint16
	ipHdrType uint16
	direction uint8
	cgroupID  uint64
	timestamp uint64
	buf       [16 * pktChunkBufLen]byte // 16 * 4080 = 65280 bytes max
	len       uint32
	firstSeen time.Time
}

// pktBufferPool reuses pktBuffer allocations across reassembly cycles.
var pktBufferPool = sync.Pool{
	New: func() interface{} { return &pktBuffer{} },
}

// PacketsPoller drains the ka_pkts_buffer perf event array, reassembles
// chunked raw network packets, and delivers complete RawPackets to a
// registered handler.
//
// Key design points:
//   - Per-CPU packet maps avoid lock contention (each CPU has its own
//     in-flight chunk map, matching BPF's per-CPU packet ID space).
//   - Background stale-packet cleanup prevents memory leaks from lost chunks.
//   - Worker pool dispatches packet processing off the polling hot path.
type PacketsPoller struct {
	chunksReader *perf.Reader
	onPacket     func(*RawPacket)

	// Per-CPU in-flight chunk reassembly state.
	pktsMaps   []map[uint64]*pktBuffer
	pktsMapsMu sync.Mutex
	maxCPUs    int

	// Worker pool for heavy-weight packet processing.
	workerJobs chan *RawPacket
	workerPool []chan struct{}

	// Lifecycle.
	stopCleanup chan struct{}
	pollWg      sync.WaitGroup // tracks the poll() goroutine for clean shutdown
	started     atomic.Bool
	reusableRec perf.Record

	// Stats.
	stats PacketsPollerStats
}

// PacketsPollerStats tracks operational counters for diagnostics.
type PacketsPollerStats struct {
	ChunksGot     uint64
	ChunksHandled uint64
	ChunksLost    uint64
	PacketsGot    uint64
	PacketsError  uint64
	WorkerDrops   uint64
}

// NewPacketsPoller creates a PacketsPoller attached to the given perf buffer.
// onPacket is invoked for each complete reassembled packet.
// perfBufferSize controls the per-CPU ring size for the perf reader.
func NewPacketsPoller(perfBuffer *ebpf.Map, onPacket func(*RawPacket), perfBufferSize int) (*PacketsPoller, error) {
	reader, err := perf.NewReader(perfBuffer, perfBufferSize)
	if err != nil {
		return nil, fmt.Errorf("PacketsPoller: perf.NewReader: %w", err)
	}

	maxCPUs := runtime.NumCPU()
	p := &PacketsPoller{
		chunksReader: reader,
		onPacket:     onPacket,
		maxCPUs:      maxCPUs,
		pktsMaps:     make([]map[uint64]*pktBuffer, maxCPUs),
		stopCleanup:  make(chan struct{}),
	}
	for i := 0; i < maxCPUs; i++ {
		p.pktsMaps[i] = make(map[uint64]*pktBuffer)
	}

	// Pre-warm pool to reduce GC pressure during startup burst.
	for i := 0; i < 64; i++ {
		pktBufferPool.Put(&pktBuffer{})
	}

	return p, nil
}

// Start launches the polling and cleanup goroutines. Non-blocking.
func (p *PacketsPoller) Start() {
	if !p.started.CompareAndSwap(false, true) {
		return
	}
	p.startWorkerPool()
	p.pollWg.Add(1)
	go func() {
		defer p.pollWg.Done()
		p.poll()
	}()
	go p.cleanupStale()
}

// Stop shuts down all goroutines and releases resources.
// Shutdown order is critical to avoid "send on closed channel" panics:
//  1. Close chunksReader → unblocks poll(), which returns on perf.ErrClosed
//  2. pollWg.Wait()     → guarantees poll() has exited (no more sends to workerJobs)
//  3. stopWorkerPool()  → safe to close workerJobs now
func (p *PacketsPoller) Stop() error {
	close(p.stopCleanup)
	err := p.chunksReader.Close() // Step 1: unblock poll()
	p.pollWg.Wait()               // Step 2: wait for poll() to fully exit
	p.stopWorkerPool()            // Step 3: now safe to close worker channel
	return err
}

// Stats returns a snapshot of operational counters.
func (p *PacketsPoller) Stats() PacketsPollerStats {
	return PacketsPollerStats{
		ChunksGot:     atomic.LoadUint64(&p.stats.ChunksGot),
		ChunksHandled: atomic.LoadUint64(&p.stats.ChunksHandled),
		ChunksLost:    atomic.LoadUint64(&p.stats.ChunksLost),
		PacketsGot:    atomic.LoadUint64(&p.stats.PacketsGot),
		PacketsError:  atomic.LoadUint64(&p.stats.PacketsError),
		WorkerDrops:   atomic.LoadUint64(&p.stats.WorkerDrops),
	}
}

// startWorkerPool launches per-CPU workers that call onPacket.
func (p *PacketsPoller) startWorkerPool() {
	numWorkers := runtime.NumCPU()
	p.workerJobs = make(chan *RawPacket, numWorkers*512)
	p.workerPool = make([]chan struct{}, numWorkers)
	for i := 0; i < numWorkers; i++ {
		done := make(chan struct{})
		p.workerPool[i] = done
		go func(done chan struct{}) {
			defer close(done)
			for pkt := range p.workerJobs {
				if p.onPacket != nil {
					p.onPacket(pkt)
				}
			}
		}(done)
	}
}

// stopWorkerPool drains and closes the worker pool.
func (p *PacketsPoller) stopWorkerPool() {
	close(p.workerJobs)
	for _, done := range p.workerPool {
		<-done
	}
}

// cleanupStale removes incomplete packets that have been waiting more than
// 30 seconds (indicating lost BPF chunks due to buffer overflow).
func (p *PacketsPoller) cleanupStale() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	const staleThreshold = 30 * time.Second
	for {
		select {
		case <-ticker.C:
			threshold := time.Now().Add(-staleThreshold)
			p.pktsMapsMu.Lock()
			for i := 0; i < p.maxCPUs; i++ {
				for id, buf := range p.pktsMaps[i] {
					if buf.firstSeen.Before(threshold) {
						pktBufferPool.Put(buf)
						delete(p.pktsMaps[i], id)
					}
				}
			}
			p.pktsMapsMu.Unlock()
		case <-p.stopCleanup:
			return
		}
	}
}

// poll is the main polling loop.
func (p *PacketsPoller) poll() {
	// Drain stale records from before startup.
	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var empty perf.Record
	for {
		if err := p.chunksReader.ReadInto(&empty); errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		if err := p.chunksReader.ReadInto(&p.reusableRec); err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			return
		}

		if p.reusableRec.LostSamples != 0 {
			atomic.AddUint64(&p.stats.ChunksLost, p.reusableRec.LostSamples)
			// Purge all in-flight state for the affected CPU (chunks are gone).
			cpu := p.reusableRec.CPU
			if cpu >= 0 && cpu < p.maxCPUs {
				p.pktsMapsMu.Lock()
				for _, buf := range p.pktsMaps[cpu] {
					pktBufferPool.Put(buf)
				}
				p.pktsMaps[cpu] = make(map[uint64]*pktBuffer)
				p.pktsMapsMu.Unlock()
			}
			continue
		}
		atomic.AddUint64(&p.stats.ChunksGot, 1)

		if ok, err := p.handleChunk(&p.reusableRec); err != nil {
			atomic.AddUint64(&p.stats.PacketsError, 1)
		} else if ok {
			atomic.AddUint64(&p.stats.ChunksHandled, 1)
		}
	}
}

// handleChunk processes a single perf record, either dispatching a single-chunk
// packet immediately or accumulating it in the per-CPU reassembly map.
func (p *PacketsPoller) handleChunk(rec *perf.Record) (bool, error) {
	data := rec.RawSample
	// BPF emits sizeof(struct ka_pkt) = 4128 bytes (4124 raw + 4 trailing pad).
	// Accept anything >= pktChunkMinSize so we handle both the padded C size
	// and any exact-size variants.
	if len(data) < pktChunkMinSize {
		return false, fmt.Errorf("chunk too small: %d < %d", len(data), pktChunkMinSize)
	}

	p.pktsMapsMu.Lock()
	defer p.pktsMapsMu.Unlock()

	// Zero-copy cast: data is owned by the perf.Record buffer which stays
	// valid until the next ReadInto call.
	// #nosec G103
	chunk := (*pktChunk)(unsafe.Pointer(&data[0]))

	cpu := rec.CPU
	if cpu < 0 || cpu >= p.maxCPUs {
		return false, fmt.Errorf("invalid CPU %d", cpu)
	}
	cpuMap := p.pktsMaps[cpu]

	// Fast path: single-chunk packet (Num=0, Last=1).
	if chunk.Num == 0 && chunk.Last != 0 {
		pkt := p.buildPacket(chunk, chunk.Buf[:chunk.Len])
		select {
		case p.workerJobs <- pkt:
		default:
			atomic.AddUint64(&p.stats.WorkerDrops, 1)
		}
		atomic.AddUint64(&p.stats.PacketsGot, 1)
		return true, nil
	}

	// Multi-chunk path: find or create the in-flight buffer.
	buf, ok := cpuMap[chunk.ID]
	if !ok {
		buf = pktBufferPool.Get().(*pktBuffer)
		buf.id = chunk.ID
		buf.num = 0
		buf.len = 0
		buf.ipHdrType = chunk.IPHdrType
		buf.direction = chunk.Direction
		buf.cgroupID = chunk.CgroupID
		buf.timestamp = chunk.Timestamp
		buf.firstSeen = time.Now()
		cpuMap[chunk.ID] = buf
	}

	// Sequence check: drop if chunk arrived out of order.
	if chunk.Num != buf.num {
		pktBufferPool.Put(buf)
		delete(cpuMap, chunk.ID)
		return false, nil
	}

	// Append chunk data.
	copy(buf.buf[buf.len:], chunk.Buf[:chunk.Len])
	buf.len += chunk.Len
	buf.num++

	if chunk.Last != 0 {
		pkt := p.buildPacket(chunk, buf.buf[:buf.len])
		select {
		case p.workerJobs <- pkt:
		default:
			atomic.AddUint64(&p.stats.WorkerDrops, 1)
		}
		delete(cpuMap, chunk.ID)
		pktBufferPool.Put(buf)
		atomic.AddUint64(&p.stats.PacketsGot, 1)
	}
	return true, nil
}

// buildPacket constructs a RawPacket from chunk metadata and raw IP bytes.
func (p *PacketsPoller) buildPacket(chunk *pktChunk, data []byte) *RawPacket {
	var ts time.Time
	if chunk.Timestamp != 0 {
		ts = time.Unix(0, int64(chunk.Timestamp))
	} else {
		ts = time.Now()
	}

	payload := make([]byte, len(data))
	copy(payload, data)

	return &RawPacket{
		Timestamp: ts,
		CgroupID:  chunk.CgroupID,
		Direction: chunk.Direction,
		IPHdrType: chunk.IPHdrType,
		Data:      payload,
	}
}
