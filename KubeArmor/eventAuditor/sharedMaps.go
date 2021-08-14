// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventAuditor

import (
	"encoding/binary"
	"unsafe"
)

//#include "BPF/shared.h"
import "C"

// =========================== //
// ======= Shared Maps ======= //
// =========================== //

const (
	KAEAPatternMap       = "ka_ea_pattern_map"
	KAEAProcessSpecMap   = "ka_ea_process_spec_map"
	KAEAProcessFilterMap = "ka_ea_process_filter_map"
)

// =========================== //
// ======= Pattern Map ======= //
// =========================== //

// Maximum Length of Pattern
const PatternMaxLen = int(C.PATTERN_MAX_LEN)

// PatternMapElement Structure
type PatternMapElement struct {
	Key   PatternMapKey
	Value PatternMapValue
}

// PatternMapKey Structure
type PatternMapKey struct {
	Pattern [PatternMaxLen]byte
}

// PatternMapValue Structure
type PatternMapValue struct {
	PatternId uint32
}

// PatternMapElement SetKey Function
func (pme *PatternMapElement) SetKey(pattern string) {
	copy(pme.Key.Pattern[:PatternMaxLen], pattern)
	pme.Key.Pattern[PatternMaxLen-1] = 0
}

// PatternMapElement SetValue Function
func (pme *PatternMapElement) SetValue(value uint32) {
	pme.Value.PatternId = value
}

// PatternMapElement SetFoundValue Function (KABPFMapElement)
func (pme *PatternMapElement) SetFoundValue(value []byte) {
	pme.Value.PatternId = binary.LittleEndian.Uint32(value)
}

// PatternMapElement KeyPointer Function (KABPFMapElement)
func (pme *PatternMapElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Key)
}

// PatternMapElement ValuePointer Function (KABPFMapElement)
func (pme *PatternMapElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Value)
}

// PatternMapElement MapName Function (KABPFMapElement)
func (pme *PatternMapElement) MapName() string {
	return KAEAPatternMap
}

// =========================== //
// ==== Process Spec Map ===== //
// =========================== //

// ProcessSpecElement Structure
type ProcessSpecElement struct {
	Key   ProcessSpecKey
	Value ProcessSpecValue
}

// ProcessSpecKey Structure
type ProcessSpecKey struct {
	PidNS     uint32
	MntNS     uint32
	PatternId uint32
}

// ProcessSpecValue Structure
type ProcessSpecValue struct {
	Inspect bool
}

// ProcessSpecElement SetKey Function
func (pse *ProcessSpecElement) SetKey(pidNS, mntNS, patternId uint32) {
	pse.Key.PidNS = pidNS
	pse.Key.MntNS = mntNS
	pse.Key.PatternId = patternId
}

// ProcessSpecElement SetValue Function
func (pse *ProcessSpecElement) SetValue(inspect bool) {
	pse.Value.Inspect = inspect
}

// ProcessSpecElement SetFoundValue Function (KABPFMapElement)
func (pse *ProcessSpecElement) SetFoundValue(value []byte) {
	pse.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

// ProcessSpecElement KeyPointer Function (KABPFMapElement)
func (pse *ProcessSpecElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Key)
}

// ProcessSpecElement ValuePointer Function (KABPFMapElement)
func (pse *ProcessSpecElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Value)
}

// ProcessSpecElement MapName Function (KABPFMapElement)
func (pse *ProcessSpecElement) MapName() string {
	return KAEAProcessSpecMap
}

// =========================== //
// === Process Filter Map ==== //
// =========================== //

// ProcessFilterElement Structure
type ProcessFilterElement struct {
	Key   ProcessFilterKey
	Value ProcessFilterValue
}

// ProcessFilterKey Structure
type ProcessFilterKey struct {
	PidNS   uint32
	MntNS   uint32
	HostPID uint32
}

// ProcessFilterValue Structure
type ProcessFilterValue struct {
	Inspect bool
}

// ProcessFilterElement SetKey Function
func (pfe *ProcessFilterElement) SetKey(pidNS, mntNS, hostPID uint32) {
	pfe.Key.PidNS = pidNS
	pfe.Key.MntNS = mntNS
	pfe.Key.HostPID = hostPID
}

// ProcessFilterElement SetValue Function
func (pfe *ProcessFilterElement) SetValue(inspect bool) {
	pfe.Value.Inspect = inspect
}

// ProcessFilterElement SetFoundValue Function (KABPFMapElement)
func (pfe *ProcessFilterElement) SetFoundValue(value []byte) {
	pfe.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

// ProcessFilterElement KeyPointer Function (KABPFMapElement)
func (pfe *ProcessFilterElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Key)
}

// ProcessFilterElement ValuePointer Function (KABPFMapElement)
func (pfe *ProcessFilterElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Value)
}

// ProcessFilterElement MapName Function (KABPFMapElement)
func (pfe *ProcessFilterElement) MapName() string {
	return KAEAProcessFilterMap
}
