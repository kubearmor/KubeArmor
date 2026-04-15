// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package goprobe discovers Go binaries using gRPC / net/http HTTP/2
// or crypto/tls and resolves the symbol addresses + struct offsets needed
// by the BPF Go HTTP/2 uprobes (go_http2_trace.h) and Go TLS uprobes
// (go_tls_trace.h).
//
// Adapted from Pixie's uprobe_manager.cc + uprobe_symaddrs.cc.
package goprobe

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"os"
	"strings"
	"syscall"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
)

// LocType mirrors BPF enum go_location_type.
const (
	LocInvalid  uint32 = 0
	LocStack    uint32 = 1
	LocRegister uint32 = 2
)

// ArgLocation matches BPF struct go_arg_location { type, offset }.
type ArgLocation struct {
	Type   uint32
	Offset int32
}

// InvalidLoc is returned for unresolved argument locations.
var InvalidLoc = ArgLocation{Type: LocInvalid, Offset: -1}

// Offset table indices — must match go_http2_symaddrs.h enum go_offset_kind.
const (
	GoOffGRPCStreamMethod       = 0
	GoOffGRPCStreamID           = 1
	GoOffGRPCTransportConn      = 2
	GoOffGRPCStatusS            = 3
	GoOffGRPCStatusCode         = 4
	GoOffFDSysfd                = 5
	GoOffConnFD                 = 6
	GoOffFDLaddr                = 7
	GoOffFDRaddr                = 8
	GoOffTCPAddrPort            = 9
	GoOffTCPAddrIP              = 10
	GoOffGRPCV160               = 11
	GoOffGRPCV169               = 12
	GoOffGRPCServerStreamStream = 13
	GoOffGRPCServerStreamST     = 14
	GoOffGRPCStreamST           = 15
	GoOffTLSConnConn            = 16
	GoOffMetaFieldsPtr          = 17 // offset of Fields.Ptr in MetaHeadersFrame
	GoOffMetaFieldsLen          = 18 // offset of Fields.Len in MetaHeadersFrame
	GoOffHframeStreamID         = 19 // offset of StreamID in FrameHeader
	GoOffHfieldSize             = 20 // sizeof(hpack.HeaderField)
	GoOffLoopyWriterFramer      = 21 // loopyWriter → framer (Framer ptr)
	GoOffH2SCHpackEncoder       = 22 // http2serverConn → hpackEncoder ptr
	GoOffH2SCConn               = 23 // http2serverConn → conn (net.Conn iface)
	GoOffWriteResStreamID       = 24 // http2writeResHeaders → streamID
	GoOffWriteResEndStream      = 25 // http2writeResHeaders → endStream
	GoOffMax                    = 26
)

// GoOffsetTable matches BPF struct go_offset_table.
// Populated per-binary and pushed to BPF map keyed by inode.
type GoOffsetTable struct {
	Offsets [GoOffMax]int64
}



// GoUProbeTarget is a Go binary that has gRPC / HTTP/2 symbols.
type GoUProbeTarget struct {
	// PID that uses this binary.
	PID uint32
	// Host path to the ELF binary (resolved through /proc/PID/root).
	BinaryPath string
	// Inode of the binary (for offset table BPF map key).
	Inode uint64
	// Resolved symbol addresses for uprobe attachment.
	Symbols map[string]uint64
	// Offset table pushed to BPF map.
	OffsetTable GoOffsetTable
	// GoTlsOffsets holds crypto/tls.(*Conn).Write/Read entry+ret offsets.
	// Nil when the binary doesn't use crypto/tls.
	GoTlsOffsets *GoTlsOffsets
}

// TargetSymbols are the Go function symbols we want to attach uprobes to.
// Keys are short IDs used for probe attachment, values are candidate symbol names.
// Adapted from OpenTelemetry's go_grpc.c probe targets.
var TargetSymbols = map[string][]string{
	"server_handleStream": {
		"google.golang.org/grpc.(*Server).handleStream",
	},
	"transport_writeStatus": {
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus",
	},
	"ClientConn_Invoke": {
		"google.golang.org/grpc.(*ClientConn).Invoke",
	},
	"ClientConn_NewStream": {
		"google.golang.org/grpc.(*ClientConn).NewStream",
	},
	"clientStream_RecvMsg": {
		"google.golang.org/grpc.(*clientStream).RecvMsg",
	},
	"operate_headers_server": {
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders",
	},
	"operate_headers_client": {
		"google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders",
	},
	"net_http_processHeaders": {
		"net/http.(*http2serverConn).processHeaders",
	},
	"loopy_writer_write_header": {
		"google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader",
	},
	"hpack_write_field": {
		"golang.org/x/net/http2/hpack.(*Encoder).WriteField",
	},
	"http2_write_res_headers": {
		"net/http.(*http2writeResHeaders).writeFrame",
	},
	// Go crypto/tls — entry probes only.
	// Return probes use ret-instruction offsets (not uretprobes) and are
	// attached separately via GoTlsOffsets. See attachGoHTTP2Uprobes.
	"go_tls_write": {
		"crypto/tls.(*Conn).Write",
	},
	"go_tls_read": {
		"crypto/tls.(*Conn).Read",
	},
}

// ScanProc scans /proc for Go binaries that use gRPC or net/http HTTP/2.
// Returns a list of targets suitable for uprobe attachment.
func ScanProc() ([]GoUProbeTarget, error) {
	entries, err := os.ReadDir(ssl.ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", ssl.ProcRoot, err)
	}

	// Track binary→PIDs to avoid redundant ELF analysis.
	type pidEntry struct {
		pid      uint32
		exePath  string
		hostPath string
	}
	binMap := make(map[string][]pidEntry)

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		if pid == 0 {
			continue
		}
		// Skip our own process — attaching uprobes to ourselves corrupts
		// the Go runtime stack during dynamic stack growth, causing
		// "unexpected return pc" panics in the K8s client JSON decoder.
		if pid == 1 || ssl.IsSelfProcess(int(pid)) {
			continue
		}
		exeLink := fmt.Sprintf("%s/%d/exe", ssl.ProcRoot, pid)
		exePath, err := os.Readlink(exeLink)
		if err != nil {
			continue
		}
		// Resolve through procfs root for containerised binaries.
		hostPath := fmt.Sprintf("%s/%d/root%s", ssl.ProcRoot, pid, exePath)
		if _, err := os.Stat(hostPath); err != nil {
			hostPath = exePath
		}
		binMap[hostPath] = append(binMap[hostPath], pidEntry{pid: pid, exePath: exePath, hostPath: hostPath})
	}

	var targets []GoUProbeTarget
	for hostPath, pids := range binMap {
		// Quick check: is it a Go binary?
		if !isGoBinary(hostPath) {
			continue
		}

		// Open ELF and look for gRPC symbols.
		ef, err := elf.Open(hostPath)
		if err != nil {
			continue
		}

		syms, err := resolveSymbols(ef, hostPath)
		ef.Close()
		if err != nil {
			continue
		}
		if len(syms) == 0 {
			continue
		}

		kg.Debugf("Found Go HTTP/2 binary for uprobe path=%s pids=%d symbols=%d",
			hostPath, len(pids), len(syms))

		// Build offset table with defaults.
		offTable := DefaultOffsetTable()

		// Detect gRPC version and apply version-specific offsets.
		grpcVer := GetGrpcLibVersion(hostPath)
		ApplyVersionOffsets(&offTable, grpcVer)

		// Resolve inode for BPF map key.
		var inode uint64
		if fi, err := os.Stat(hostPath); err == nil {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
		}

		// Discover Go TLS ret instruction offsets for uprobe-at-ret pattern.
		var tlsOffsets *GoTlsOffsets
		if _, hasTLS := syms["go_tls_write"]; hasTLS {
			offsets, tlsErr := FindGoTlsOffsets(hostPath)
			if tlsErr != nil {
				kg.Warnf("Go TLS offset discovery failed (uretprobe fallback disabled) path=%s err=%v",
					hostPath, tlsErr)
			} else {
				tlsOffsets = &offsets
				kg.Debugf("Go TLS ret offsets discovered path=%s write_exits=%d read_exits=%d abi=%d",
					hostPath, len(offsets.GoWriteOffset.Exits), len(offsets.GoReadOffset.Exits), offsets.Abi)
			}
		}

		for _, pe := range pids {
			targets = append(targets, GoUProbeTarget{
				PID:          pe.pid,
				BinaryPath:   pe.hostPath,
				Inode:        inode,
				Symbols:      syms,
				OffsetTable:  offTable,
				GoTlsOffsets: tlsOffsets,
			})
		}
	}

	return targets, nil
}



// isGoBinary checks if a binary contains Go build info.
func isGoBinary(path string) bool {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return false
	}
	return info.GoVersion != ""
}

// resolveSymbols looks up the target function symbols in the ELF binary.
// Returns a map of short_id → virtual address.
func resolveSymbols(ef *elf.File, path string) (map[string]uint64, error) {
	allSyms, err := ef.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read symbols from %s: %w", path, err)
	}

	// Build a map of name → file offset for quick lookup.
	// cilium/ebpf's UprobeOptions.Address expects file offsets, not virtual
	// addresses. Convert using: offset = sym.Value - prog.Vaddr + prog.Off
	// (same logic as cilium/ebpf internal symbol resolution).
	symMap := make(map[string]uint64, len(allSyms))
	for _, s := range allSyms {
		if s.Value == 0 {
			continue
		}
		// Convert vaddr → file offset using program headers.
		offset := s.Value
		for _, prog := range ef.Progs {
			if prog.Type != elf.PT_LOAD {
				continue
			}
			if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
				offset = s.Value - prog.Vaddr + prog.Off
				break
			}
		}
		symMap[s.Name] = offset
	}

	result := make(map[string]uint64)
	for shortID, candidates := range TargetSymbols {
		for _, candidate := range candidates {
			// Try exact match first, then vendor-prefixed match.
			if addr, ok := symMap[candidate]; ok {
				result[shortID] = addr
				break
			}
			// Try with vendor prefix: look for suffix match.
			for name, addr := range symMap {
				if strings.HasSuffix(name, candidate) {
					result[shortID] = addr
					break
				}
			}
		}
	}

	return result, nil
}

