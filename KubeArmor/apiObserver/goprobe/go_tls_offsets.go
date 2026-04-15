// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// Ported from kubeshark/tracer pkg/hooks/go/go_offsets.go (GPL-3.0)
//
// Finds crypto/tls symbol offsets + all `ret` instruction offsets
// via disassembly using golang.org/x/arch (pure Go, no CGO dependency).
// Supports both amd64 and arm64 architectures.
//
// This is necessary because uretprobes crash Go programs due to
// goroutine stack relocation.

package goprobe

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"os"
	"regexp"
	"runtime"
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// GoTlsAbi determines the Go calling convention.
type GoTlsAbi int

const (
	GoABI0        GoTlsAbi = iota // Stack-based (Go < 1.17)
	GoABIInternal                 // Register-based (Go >= 1.17)
)

const PtrSize = 8

// GoTlsExtendedOffset holds the function entry offset and all `ret` offsets.
type GoTlsExtendedOffset struct {
	Enter uint64
	Exits []uint64 // All `ret` instruction file offsets
}

// NetConnOffset describes how to reach the FD from a net.Conn interface.
type NetConnOffset struct {
	SymbolOffset      uint64
	SocketSysFdOffset int64
	IsGoInterface     uint8
}

// GoTlsOffsets is the result of scanning a Go binary for TLS probe targets.
type GoTlsOffsets struct {
	GoWriteOffset  *GoTlsExtendedOffset
	GoReadOffset   *GoTlsExtendedOffset
	GoVersion      string
	Abi            GoTlsAbi
	GoidOffset     uint64
	GStructOffset  uint64
	NetConnOffsets map[string]*NetConnOffset
}

const (
	minimumABIInternalGoVersion = "1.17.0"
	goVersionSymbol             = "runtime.buildVersion.str"
	goTlsWriteSymbol            = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol             = "crypto/tls.(*Conn).Read"
)

// FindGoTlsOffsets scans a Go binary for crypto/tls symbols and disassembles
// them to find all `ret` instruction offsets.
func FindGoTlsOffsets(fpath string) (GoTlsOffsets, error) {
	offsets := map[string]*GoTlsExtendedOffset{
		goVersionSymbol:  nil,
		goTlsWriteSymbol: nil,
		goTlsReadSymbol:  nil,
	}

	// DWARF errors (stripped binaries) are non-fatal — we still need the
	// ret instruction offsets even if we can't resolve goid/gStructOffset.
	goidOffset, gStructOffset, netConnOffsets, err := findGoSymbolOffsets(fpath, offsets)
	if err != nil {
		kg.Warnf("Go TLS: DWARF/symbol scan partial failure (continuing with ret offsets) path=%s err=%v",
			fpath, err)
	}

	abi := GoABI0
	var passed bool
	var goVersion string

	goVersionOffset := offsets[goVersionSymbol]
	if goVersionOffset != nil {
		passed, goVersion, err = checkGoVersionFromBinary(fpath, goVersionOffset)
		if err != nil {
			// Version check failure is non-fatal — default to ABI0.
			kg.Warnf("Go TLS: version check failed (defaulting to ABIInternal for modern Go) path=%s err=%v",
				fpath, err)
			// Most Go binaries in production are >= 1.17; default to ABIInternal.
			passed = true
		}
	} else {
		// No version symbol found — assume modern Go with register ABI.
		passed = true
	}

	if passed {
		abi = GoABIInternal
	}

	writeOffset := offsets[goTlsWriteSymbol]
	if writeOffset == nil {
		return GoTlsOffsets{}, fmt.Errorf("symbol %s not found", goTlsWriteSymbol)
	}

	readOffset := offsets[goTlsReadSymbol]
	if readOffset == nil {
		return GoTlsOffsets{}, fmt.Errorf("symbol %s not found", goTlsReadSymbol)
	}

	kg.Debugf("Go TLS offsets found version=%s abi=%d write_enter=%d write_exits=%d read_enter=%d read_exits=%d",
		goVersion, abi, writeOffset.Enter, len(writeOffset.Exits), readOffset.Enter, len(readOffset.Exits))

	return GoTlsOffsets{
		GoWriteOffset:  writeOffset,
		GoReadOffset:   readOffset,
		GoVersion:      goVersion,
		Abi:            abi,
		GoidOffset:     goidOffset,
		GStructOffset:  gStructOffset,
		NetConnOffsets: netConnOffsets,
	}, nil
}

func getGStructOffset(exe *elf.File) (gStructOffset uint64, err error) {
	var tls *elf.Prog
	for _, prog := range exe.Progs {
		if prog.Type == elf.PT_TLS {
			tls = prog
			break
		}
	}

	switch exe.Machine {
	case elf.EM_X86_64, elf.EM_386:
		tlsg, _ := getSymbolFromElf(exe, "runtime.tlsg")
		if tlsg == nil || tls == nil {
			gStructOffset = ^uint64(PtrSize) + 1 // -ptrSize
			return gStructOffset, nil
		}
		memsz := tls.Memsz + (-tls.Vaddr-tls.Memsz)&(tls.Align-1)
		gStructOffset = ^(memsz) + 1 + tlsg.Value

	case elf.EM_AARCH64:
		tlsg, _ := getSymbolFromElf(exe, "runtime.tls_g")
		if tlsg == nil || tls == nil {
			gStructOffset = 2 * uint64(PtrSize)
			return gStructOffset, nil
		}
		gStructOffset = tlsg.Value + uint64(PtrSize*2) +
			((tls.Vaddr - uint64(PtrSize*2)) & (tls.Align - 1))

	default:
		err = fmt.Errorf("architecture not supported: %v", exe.Machine)
	}

	return gStructOffset, err
}

var regexpNetConn = regexp.MustCompile(`go:itab\.\*([^,]+),net.Conn`)

func populateNetConnOffsetFromDwarf(dwarfData *dwarf.Data, entry *dwarf.Entry,
	netConnOffsets map[string]*NetConnOffset) {
	if entry.Tag != dwarf.TagStructType {
		return
	}
	attr := entry.Val(dwarf.AttrName)
	structName, ok := attr.(string)
	if !ok {
		return
	}

	offset, ok := netConnOffsets[structName]
	if !ok {
		return
	}

	typEntry, err := dwarfData.Type(entry.Offset)
	if err != nil {
		return
	}
	name, ok := typEntry.(*dwarf.StructType)
	if !ok {
		return
	}
	for _, field := range name.Field {
		if field.Type.String() == "net.conn" {
			offset.IsGoInterface = 0
		} else if field.Type.String() == "net.Conn" {
			offset.IsGoInterface = 1
		} else {
			continue
		}
		// net.conn has net.netFD where sysFd is at offset 0x10(16)
		offset.SocketSysFdOffset = 16 + field.ByteOffset
		kg.Debugf("Found custom socket name=%s type=%s offset=%d",
			structName, field.Type.String(), offset.SocketSysFdOffset)
		return
	}
}

func getGoidOffset(elfFile *elf.File, netConnOffsets map[string]*NetConnOffset) (
	goidOffset uint64, gStructOffset uint64, err error) {

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		return 0, 0, err
	}

	entryReader := dwarfData.Reader()
	var runtimeGOffset uint64
	var seenRuntimeG, seenGoid bool

	for {
		entry, err := entryReader.Next()
		if err == io.EOF || entry == nil {
			break
		}

		populateNetConnOffsetFromDwarf(dwarfData, entry, netConnOffsets)

		if !seenRuntimeG && entry.Tag == dwarf.TagStructType {
			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrName {
					if val, ok := field.Val.(string); ok && val == "runtime.g" {
						runtimeGOffset = uint64(entry.Offset)
						seenRuntimeG = true
					}
				}
			}
		}

		if !seenGoid && seenRuntimeG && entry.Tag == dwarf.TagMember {
			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrName {
					if val, ok := field.Val.(string); ok && val == "goid" {
						goidOffset = uint64(entry.Offset) - runtimeGOffset - 0x4b
						gStructOffset, err = getGStructOffset(elfFile)
						if err != nil {
							return 0, 0, err
						}
						seenGoid = true
					}
				}
			}
		}
	}

	if !seenGoid {
		err = fmt.Errorf("goid not found in DWARF")
	}
	return goidOffset, gStructOffset, err
}

// findRetOffsetsAmd64 disassembles x86-64 machine code and returns positions
// of all RET instructions using golang.org/x/arch/x86/x86asm.
func findRetOffsetsAmd64(symBytes []byte, symVaddr uint64, lastProg *elf.Prog) []uint64 {
	var exits []uint64
	pos := 0
	for pos < len(symBytes) {
		inst, err := x86asm.Decode(symBytes[pos:], 64)
		if err != nil {
			pos++
			continue
		}
		if inst.Op == x86asm.RET {
			exitOffset := (symVaddr + uint64(pos)) - lastProg.Vaddr + lastProg.Off
			exits = append(exits, exitOffset)
		}
		pos += inst.Len
	}
	return exits
}

// findRetOffsetsArm64 disassembles ARM64 machine code and returns positions
// of all RET instructions using golang.org/x/arch/arm64/arm64asm.
// ARM64 instructions are fixed 4 bytes.
func findRetOffsetsArm64(symBytes []byte, symVaddr uint64, lastProg *elf.Prog) []uint64 {
	var exits []uint64
	const instrSize = 4
	for pos := 0; pos+instrSize <= len(symBytes); pos += instrSize {
		inst, err := arm64asm.Decode(symBytes[pos : pos+instrSize])
		if err != nil {
			continue
		}
		if inst.Op == arm64asm.RET {
			exitOffset := (symVaddr + uint64(pos)) - lastProg.Vaddr + lastProg.Off
			exits = append(exits, exitOffset)
		}
	}
	return exits
}

// findRetOffsets dispatches to the arch-specific disassembler based on
// runtime.GOARCH. The ELF machine type corresponds to the binary being
// analyzed (target), while GOARCH is the host where probes will be attached.
func findRetOffsets(symBytes []byte, symVaddr uint64, lastProg *elf.Prog) []uint64 {
	switch runtime.GOARCH {
	case "amd64":
		return findRetOffsetsAmd64(symBytes, symVaddr, lastProg)
	case "arm64":
		return findRetOffsetsArm64(symBytes, symVaddr, lastProg)
	default:
		kg.Warnf("Unsupported GOARCH for ret-probing arch=%s", runtime.GOARCH)
		return nil
	}
}

func findGoSymbolOffsets(fpath string, offsets map[string]*GoTlsExtendedOffset) (
	goidOffset uint64, gStructOffset uint64,
	netConnOffsets map[string]*NetConnOffset, err error) {

	fd, err := os.Open(fpath)
	if err != nil {
		return 0, 0, nil, err
	}
	defer fd.Close()

	elfFile, err := elf.NewFile(fd)
	if err != nil {
		return 0, 0, nil, err
	}

	textSection := elfFile.Section(".text")
	if textSection == nil {
		return 0, 0, nil, fmt.Errorf("no .text section")
	}

	textSectionFile := textSection.Open()

	syms, err := elfFile.Symbols()
	if err != nil {
		return 0, 0, nil, err
	}

	netConnOffsets = make(map[string]*NetConnOffset)
	for _, sym := range syms {
		matches := regexpNetConn.FindStringSubmatch(sym.Name)
		if len(matches) == 2 {
			netConnOffsets[matches[1]] = &NetConnOffset{
				SymbolOffset:      sym.Value,
				SocketSysFdOffset: -1,
			}
		}

		if _, ok := offsets[sym.Name]; !ok {
			continue
		}

		offset := sym.Value
		var lastProg *elf.Prog
		for _, prog := range elfFile.Progs {
			if prog.Vaddr <= sym.Value && sym.Value < (prog.Vaddr+prog.Memsz) {
				offset = sym.Value - prog.Vaddr + prog.Off
				lastProg = prog
				break
			}
		}

		extendedOffset := &GoTlsExtendedOffset{Enter: offset}

		// Skip non-function symbols.
		if sym.Info != 2 && sym.Info != 18 {
			offsets[sym.Name] = extendedOffset
			continue
		}
		if sym.Size == 0 {
			offsets[sym.Name] = extendedOffset
			continue
		}

		// Read the symbol bytes from .text section.
		symStartIdx := sym.Value - textSection.Addr
		symEndIdx := symStartIdx + sym.Size

		if symEndIdx > uint64(textSection.Size-1) {
			kg.Warnf("Symbol too large, skipping symbol=%s endIdx=%d textSize=%d",
				sym.Name, symEndIdx, textSection.Size)
			continue
		}

		if _, err = textSectionFile.Seek(int64(symStartIdx), io.SeekStart); err != nil {
			return 0, 0, netConnOffsets, err
		}

		num := int(symEndIdx - symStartIdx)
		symBytes := make([]byte, num)
		numRead, err := textSectionFile.Read(symBytes)
		if err != nil {
			return 0, 0, netConnOffsets, err
		}
		if numRead != num {
			return 0, 0, netConnOffsets, errors.New("text section read failed")
		}

		// Disassemble to find all `ret` instructions.
		if lastProg != nil {
			extendedOffset.Exits = findRetOffsets(symBytes, sym.Value, lastProg)
		}

		offsets[sym.Name] = extendedOffset
	}

	goidOffset, gStructOffset, err = getGoidOffset(elfFile, netConnOffsets)
	return goidOffset, gStructOffset, netConnOffsets, err
}

func checkGoVersionFromBinary(fpath string, offset *GoTlsExtendedOffset) (bool, string, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return false, "", err
	}
	defer fd.Close()

	reader := bufio.NewReader(fd)

	if _, err = reader.Discard(int(offset.Enter)); err != nil {
		return false, "", err
	}

	line, err := reader.ReadString(0)
	if err != nil {
		return false, "", err
	}

	if len(line) < 3 {
		return false, "", fmt.Errorf("ELF data segment read error (corrupted)")
	}

	goVersionStr := line[2 : len(line)-1]

	// Go embeds version strings like "go1.22.0" — strip the "go" prefix
	// so semver can parse it as "1.22.0".
	cleanVersion := strings.TrimPrefix(goVersionStr, "go")

	goVersion, err := semver.NewVersion(cleanVersion)
	if err != nil {
		return false, goVersionStr, fmt.Errorf("invalid semantic version %q (cleaned: %q): %w", goVersionStr, cleanVersion, err)
	}

	constraint, err := semver.NewConstraint(fmt.Sprintf(">= %s", minimumABIInternalGoVersion))
	if err != nil {
		return false, goVersionStr, err
	}

	return constraint.Check(goVersion), goVersionStr, nil
}

func getSymbolFromElf(exe *elf.File, name string) (*elf.Symbol, error) {
	symbols, err1 := exe.Symbols()
	if err1 != nil {
		symbols = []elf.Symbol{}
	}

	dynSymbols, err2 := exe.DynamicSymbols()
	if err2 == nil {
		symbols = append(symbols, dynSymbols...)
	}

	if len(symbols) == 0 {
		if !errors.Is(err1, elf.ErrNoSymbols) {
			return nil, err1
		}
		if !errors.Is(err2, elf.ErrNoSymbols) {
			return nil, err2
		}
	}

	for _, symbol := range symbols {
		if symbol.Name == name {
			return &symbol, nil
		}
	}

	return nil, fmt.Errorf("symbol '%s' not found", name)
}
