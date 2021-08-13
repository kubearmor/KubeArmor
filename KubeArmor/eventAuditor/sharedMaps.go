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

const PatternMaxLen = int(C.PATTERN_MAX_LEN)

type PatternMapElement struct {
	Key   PatternMapKey
	Value PatternMapValue
}

type PatternMapKey struct {
	Pattern [PatternMaxLen]byte
}

type PatternMapValue struct {
	PatternId uint32
}

func (pme *PatternMapElement) SetKey(pattern string) {
	copy(pme.Key.Pattern[:PatternMaxLen], pattern)
	pme.Key.Pattern[PatternMaxLen-1] = 0
}

func (pme *PatternMapElement) SetValue(value uint32) {
	pme.Value.PatternId = value
}

func (pme *PatternMapElement) SetFoundValue(value []byte) {
	pme.Value.PatternId = binary.LittleEndian.Uint32(value)
}

func (pme *PatternMapElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Key)
}

func (pme *PatternMapElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Value)
}

func (pme *PatternMapElement) MapName() string {
	return KAEAPatternMap
}

// =========================== //
// ==== Process Spec Map ===== //
// =========================== //

type ProcessSpecElement struct {
	Key   ProcessSpecKey
	Value ProcessSpecValue
}

type ProcessSpecKey struct {
	PidNS     uint32
	MntNS     uint32
	PatternId uint32
}

type ProcessSpecValue struct {
	Inspect bool
}

func (pse *ProcessSpecElement) SetKey(pidNS, mntNS, patternId uint32) {
	pse.Key.PidNS = pidNS
	pse.Key.MntNS = mntNS
	pse.Key.PatternId = patternId
}

func (pse *ProcessSpecElement) SetValue(inspect bool) {
	pse.Value.Inspect = inspect
}

func (pse *ProcessSpecElement) SetFoundValue(value []byte) {
	pse.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

func (pse *ProcessSpecElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Key)
}

func (pse *ProcessSpecElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Value)
}

func (pse *ProcessSpecElement) MapName() string {
	return KAEAProcessSpecMap
}

// =========================== //
// === Process Filter Map ==== //
// =========================== //

type ProcessFilterElement struct {
	Key   ProcessFilterKey
	Value ProcessFilterValue
}

type ProcessFilterKey struct {
	PidNS   uint32
	MntNS   uint32
	HostPID uint32
}

type ProcessFilterValue struct {
	Inspect bool
}

func (pfe *ProcessFilterElement) SetKey(pidNS, mntNS, hostPID uint32) {
	pfe.Key.PidNS = pidNS
	pfe.Key.MntNS = mntNS
	pfe.Key.HostPID = hostPID
}

func (pfe *ProcessFilterElement) SetValue(inspect bool) {
	pfe.Value.Inspect = inspect
}

func (pfe *ProcessFilterElement) SetFoundValue(value []byte) {
	pfe.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

func (pfe *ProcessFilterElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Key)
}

func (pfe *ProcessFilterElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Value)
}

func (pfe *ProcessFilterElement) MapName() string {
	return KAEAProcessFilterMap
}
