// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// ssl/symaddrs.go — Runtime detection of OpenSSL struct field offsets.
// TODO: Work in progress - not tested
//
//	bcc_bpf_intf/symaddrs.h  (table) +
//	openssl_trace_bpf_funcs.h (FD extraction logic)
//
//	The internal layout of OpenSSL's SSL and BIO structs changed across
//	major versions. We cannot use CGO offsetof() at runtime (no headers),
//	so we maintain a version-keyed lookup table and confirm the version
//	by scanning the .rodata section of the library itself.
package ssl

import (
	"debug/elf"
	"fmt"
	"path/filepath"
	"strings"
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

// versionOffsets maps an OpenSSL/BoringSSL version prefix to the correct
// struct field offsets. Add new entries here when new major versions ship.
//
// Values verified against OpenSSL source:
//
//	1.0.x  ssl/ssl_locl.h   — ssl->rbio at +96,  bio->num at +40
//	1.1.x  ssl/ssl_local.h  — ssl->rbio at +16,  bio->num at +48
//	3.x    ssl/ssl_local.h  — same layout as 1.1.x
//	BoringSSL               — matches 1.1.x layout
var versionOffsets = map[string]SymAddrs{
	"OpenSSL 1.0": {SSLRBIOOffset: 96, BIONumOffset: 40},
	"OpenSSL 1.1": {SSLRBIOOffset: 16, BIONumOffset: 48},
	"OpenSSL 3.":  {SSLRBIOOffset: 16, BIONumOffset: 48},
	"BoringSSL":   {SSLRBIOOffset: 16, BIONumOffset: 48},
}

// libSSLGlobs lists glob patterns covering the most common libssl install
// paths across Debian/Ubuntu, RHEL/Fedora, Alpine, and their arm64 variants.
var libSSLGlobs = []string{
	"/usr/lib/x86_64-linux-gnu/libssl.so.*",
	"/usr/lib/aarch64-linux-gnu/libssl.so.*",
	"/usr/lib64/libssl.so.*",
	"/usr/lib/libssl.so.*",
	"/lib/x86_64-linux-gnu/libssl.so.*",
	"/lib/aarch64-linux-gnu/libssl.so.*",
	"/lib64/libssl.so.*",
	// Container base images often install to /usr/local
	"/usr/local/lib/libssl.so.*",
	"/usr/local/lib64/libssl.so.*",
}

// LibSSLPaths returns all concrete libssl.so.* paths found on the system,
// de-duplicated. Returns an error only if none are found.
func LibSSLPaths() ([]string, error) {
	seen := make(map[string]struct{})
	var result []string

	for _, pattern := range libSSLGlobs {
		matches, _ := filepath.Glob(pattern) // Glob never errors on valid pattern
		for _, m := range matches {
			if _, dup := seen[m]; !dup {
				seen[m] = struct{}{}
				result = append(result, m)
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("libssl.so not found on system (checked %d glob patterns)",
			len(libSSLGlobs))
	}
	return result, nil
}

// OffsetsForLib detects the OpenSSL version embedded in the given shared
// library and returns the struct field offsets needed by the BPF uprobe.
//
// It reads the version string directly from the ELF .rodata section —
// no dlopen, no CGO, no subprocess.  Works inside a container even when
// the system's openssl(1) binary is absent.
func OffsetsForLib(libPath string) (SymAddrs, error) {
	version, err := versionStringFromELF(libPath)
	if err != nil {
		return SymAddrs{}, fmt.Errorf("reading OpenSSL version from %s: %w", libPath, err)
	}

	for prefix, offsets := range versionOffsets {
		if strings.HasPrefix(version, prefix) {
			return offsets, nil
		}
	}

	// Fallback: use filename (SONAME suffix).
	// On many systems (like Arch), the string might be stripped, but
	// the filename "libssl.so.3" or "libssl.so.1.1" tells us the version.
	filename := filepath.Base(libPath)
	if strings.Contains(filename, "libssl.so.3") {
		return versionOffsets["OpenSSL 3."], nil
	} else if strings.Contains(filename, "libssl.so.1.1") {
		return versionOffsets["OpenSSL 1.1"], nil
	} else if strings.Contains(filename, "libssl.so.1.0") {
		return versionOffsets["OpenSSL 1.0"], nil
	}

	return SymAddrs{}, fmt.Errorf(
		"unsupported OpenSSL version %q (and filename %q not recognized)",
		version, filename,
	)
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
