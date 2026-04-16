// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// ssl/symaddrs.go — Runtime detection of OpenSSL struct field offsets
// and per-PID /proc/maps-based SSL library discovery.
//
// Two FD extraction strategies (ported from Pixie):
//   - SSLFDNestedSyscall:    BPF kprobes capture the FD from inner syscalls (OpenSSL, Python)
//   - SSLFDUserSpaceOffsets: BPF walks ssl->rbio->num using version-specific offsets (Netty/BoringSSL)
//
// The internal layout of OpenSSL's SSL and BIO structs changed across
// major versions. We read the version from the ELF .rodata section and
// return the matching offsets.
package ssl

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SSLSocketFDAccess defines how the FD is extracted for a given SSL library.
type SSLSocketFDAccess int

const (
	// SSLFDNestedSyscall means the FD is captured by inner write()/read() syscalls
	// while SSL_write/SSL_read is on the stack. Works for OpenSSL, Python, static builds.
	SSLFDNestedSyscall SSLSocketFDAccess = iota
	// SSLFDUserSpaceOffsets means the FD is extracted by walking ssl->rbio->num
	// using version-specific struct field offsets. Required for Netty/BoringSSL.
	SSLFDUserSpaceOffsets
)

// SymAddrs holds the two field offsets the BPF uprobe needs to extract
// a file descriptor from an SSL*.
//
// BPF usage (openssl_trace.h):
//
//	rbio = *(void**)((u8*)ssl  + ssl_rbio_offset)  // SSL → BIO*
//	fd   = *(int*)  ((u8*)rbio + bio_num_offset)   // BIO → fd
//
// MUST stay in sync with struct ssl_symaddrs in common/structs.h.
type SymAddrs struct {
	SSLRBIOOffset int32 // offsetof(SSL, rbio)
	BIONumOffset  int32 // offsetof(BIO, num)
}

// SSLLibMatcher defines how to search for an SSL library in /proc/maps.
// Ported from Pixie uprobe_manager.h kLibSSLMatchers.
type SSLLibMatcher struct {
	// LibSSL is the library name pattern to search for.
	LibSSL string
	// LibCrypto is the companion crypto library name.
	// Empty string means SSL_write/SSL_read live in LibSSL itself.
	LibCrypto string
	// SearchType controls matching: EndsWith or Contains.
	SearchType MatchType
	// SocketFDAccess controls the FD extraction strategy.
	SocketFDAccess SSLSocketFDAccess
}

// SSLLibMatch is a concrete result of matching a library for a PID.
type SSLLibMatch struct {
	// LibSSLPath is the host-accessible path to the SSL library.
	LibSSLPath string
	// PID is the process that loaded this library.
	PID int
	// Matcher is the matcher that found this library.
	Matcher SSLLibMatcher
}

// DefaultMatchers lists all SSL library patterns to search for.
// Ordering matters — first match wins for a given PID.
var DefaultMatchers = []SSLLibMatcher{
	// OpenSSL 1.1.x (Debian/Ubuntu)
	{LibSSL: "libssl.so.1.1", LibCrypto: "libcrypto.so.1.1",
		SearchType: MatchEndsWith, SocketFDAccess: SSLFDNestedSyscall},
	// OpenSSL 3.x (Ubuntu 22.04+, RHEL 9+)
	{LibSSL: "libssl.so.3", LibCrypto: "libcrypto.so.3",
		SearchType: MatchEndsWith, SocketFDAccess: SSLFDNestedSyscall},
	// Broad libssl.so matcher (catches any libssl variant in maps, like kubeshark)
	{LibSSL: "libssl.so", LibCrypto: "",
		SearchType: MatchContains, SocketFDAccess: SSLFDNestedSyscall},
	// Node.js (statically links OpenSSL into the node binary)
	{LibSSL: "node", LibCrypto: "",
		SearchType: MatchExecutable, SocketFDAccess: SSLFDNestedSyscall},
	// Envoy proxy (Istio sidecar, ingress gateways) — statically links BoringSSL.
	// BoringSSL exports the same SSL_read/SSL_write symbols as OpenSSL.
	// Reference: kubeshark tracer/pkg/discoverer/pids.go:installEnvoysslHook
	{LibSSL: "envoy", LibCrypto: "",
		SearchType: MatchExecutable, SocketFDAccess: SSLFDNestedSyscall},
	// Java/Netty tcnative (BoringSSL)
	{LibSSL: "libnetty_tcnative_linux", LibCrypto: "",
		SearchType: MatchContains, SocketFDAccess: SSLFDUserSpaceOffsets},
	// Java/Conscrypt (BoringSSL)
	{LibSSL: "libconscrypt_openjdk_jni", LibCrypto: "",
		SearchType: MatchContains, SocketFDAccess: SSLFDUserSpaceOffsets},
}

// DiscoverSSLLibsForPID scans /proc/<pid>/maps for SSL libraries using all
// configured matchers. Returns all matches found (there may be more than one
// if a process uses multiple SSL libraries).
func DiscoverSSLLibsForPID(pid int) []SSLLibMatch {
	maps, err := ParseProcMaps(pid)
	if err != nil {
		return nil
	}

	var matches []SSLLibMatch
	seenInodes := make(map[string]bool) // deduplicate by resolved host path

	for _, matcher := range DefaultMatchers {
		if matcher.SearchType == MatchExecutable {
			// For executable matchers (e.g. Node.js), check /proc/PID/exe
			exePath, err := os.Readlink(fmt.Sprintf("%s/%d/exe", ProcRoot, pid))
			if err != nil {
				continue
			}
			basename := filepath.Base(exePath)
			if !strings.Contains(basename, matcher.LibSSL) {
				continue
			}
			// Verify the binary actually exports SSL symbols
			hostPath := HostPath(pid, exePath)
			if !ELFHasSymbol(hostPath, "SSL_write") {
				continue
			}
			if seenInodes[hostPath] {
				continue
			}
			seenInodes[hostPath] = true
			matches = append(matches, SSLLibMatch{
				LibSSLPath: hostPath,
				PID:        pid,
				Matcher:    matcher,
			})
			continue
		}

		path := FindLibInMaps(maps, matcher.LibSSL, matcher.SearchType)
		if path == "" {
			continue
		}

		hostPath := HostPath(pid, path)
		if seenInodes[hostPath] {
			continue
		}
		seenInodes[hostPath] = true

		match := SSLLibMatch{
			LibSSLPath: hostPath,
			PID:        pid,
			Matcher:    matcher,
		}
		matches = append(matches, match)
	}

	return matches
}

// versionOffsets maps an OpenSSL/BoringSSL version prefix to the correct
// struct field offsets. Add new entries here when new major versions ship.
//
// Values verified against OpenSSL source and Pixie uprobe_symaddrs.cc:694-770:
//
//	OpenSSL 1.1.0:  ssl→rbio at +0x10,  bio→num at +0x28
//	OpenSSL 1.1.1:  ssl→rbio at +0x10,  bio→num at +0x30
//	OpenSSL 3.x:    ssl→rbio at +0x10,  bio→num at +0x30
//	BoringSSL:      ssl→rbio at +0x18,  bio→num at +0x18
var versionOffsets = map[string]SymAddrs{
	"OpenSSL 1.0": {SSLRBIOOffset: 0x60, BIONumOffset: 0x28},
	"OpenSSL 1.1": {SSLRBIOOffset: 0x10, BIONumOffset: 0x30},
	"OpenSSL 3.":  {SSLRBIOOffset: 0x10, BIONumOffset: 0x30},
	"BoringSSL":   {SSLRBIOOffset: 0x18, BIONumOffset: 0x18},
}

// OffsetsForLib detects the OpenSSL version embedded in the given shared
// library and returns the struct field offsets needed by the BPF uprobe.
//
// It reads the version string directly from the ELF .rodata section —
// no dlopen, no CGO, no subprocess.  Works inside a container even when
// the system's openssl(1) binary is absent.
func OffsetsForLib(libPath string) (SymAddrs, error) {
	// Check for BoringSSL by filename first (e.g. Netty tcnative)
	basename := filepath.Base(libPath)
	if strings.Contains(basename, "netty_tcnative") ||
		strings.Contains(basename, "conscrypt") {
		return versionOffsets["BoringSSL"], nil
	}

	version, err := versionStringFromELF(libPath)
	if err != nil {
		// Try filename-based fallback
		return offsetsFromFilename(basename)
	}

	for prefix, offsets := range versionOffsets {
		if strings.HasPrefix(version, prefix) {
			return offsets, nil
		}
	}

	// Fallback: use filename (SONAME suffix).
	return offsetsFromFilename(basename)
}

// offsetsFromFilename tries to determine offsets from the library filename.
func offsetsFromFilename(filename string) (SymAddrs, error) {
	switch {
	case strings.Contains(filename, "libssl.so.3"):
		return versionOffsets["OpenSSL 3."], nil
	case strings.Contains(filename, "libssl.so.1.1"):
		return versionOffsets["OpenSSL 1.1"], nil
	case strings.Contains(filename, "libssl.so.1.0"):
		return versionOffsets["OpenSSL 1.0"], nil
	default:
		return SymAddrs{}, fmt.Errorf("unrecognized SSL library filename %q", filename)
	}
}

// versionStringFromELF scans the .rodata section of libPath for an
// OPENSSL_VERSION_TEXT string (e.g. "OpenSSL 3.0.2 15 Mar 2022").
//
// OpenSSL always embeds this string as a null-terminated C string in
// .rodata; it is the most reliable version source in a stripped binary.
func versionStringFromELF(libPath string) (string, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sec := f.Section(".rodata")
	if sec == nil {
		return "", fmt.Errorf("%s has no .rodata section", libPath)
	}

	raw, err := sec.Data()
	if err != nil {
		return "", fmt.Errorf("reading .rodata from %s: %w", libPath, err)
	}

	s := string(raw)
	for _, prefix := range []string{"OpenSSL ", "BoringSSL"} {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			continue
		}
		// Version string is null-terminated; cap at 128 bytes defensively.
		tail := s[idx:]
		end := strings.IndexByte(tail, 0)
		if end < 0 || end > 128 {
			end = 128
		}
		return tail[:end], nil
	}

	return "", fmt.Errorf("OpenSSL version string not found in .rodata of %s", libPath)
}

// ELFHasSymbol checks if an ELF binary exports a given symbol name.
// Used for detecting statically-linked OpenSSL in binaries like Node.js.
func ELFHasSymbol(binPath string, symbolName string) bool {
	_, found := ELFSymbolAddress(binPath, symbolName)
	return found
}

// ELFSymbolAddress returns the virtual address of a symbol in an ELF binary.
// Checks both dynamic and static symbol tables. Returns (0, false) if not found.
// Used for resolving statically-linked symbols (e.g. SSL_write in Node.js)
// that cilium/ebpf's Uprobe() can't resolve automatically.
func ELFSymbolAddress(binPath string, symbolName string) (uint64, bool) {
	f, err := elf.Open(binPath)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	// Check dynamic symbols first (most common)
	dynsyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynsyms {
			if sym.Name == symbolName && sym.Value != 0 {
				return sym.Value, true
			}
		}
	}

	// Check regular symbols (for statically linked)
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Name == symbolName && sym.Value != 0 {
				return sym.Value, true
			}
		}
	}

	return 0, false
}
