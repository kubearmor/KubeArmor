// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

//#cgo CFLAGS: -I${SRCDIR}/../BPF
//#include "shared.h"
import "C"

import (
	"encoding/binary"
	"unsafe"
)

// =========================== //
// ======= Shared Maps ======= //
// =========================== //

// KubeArmor Event Auditor Maps
const (
	KAEAPatternMap     KABPFMapName     = "ka_ea_pattern_map"
	KAEAPatternMapFile KABPFObjFileName = "ka_ea_process.bpf.o"

	KAEAProcessSpecMap     KABPFMapName     = "ka_ea_process_spec_map"
	KAEAProcessSpecMapFile KABPFObjFileName = "ka_ea_process.bpf.o"

	KAEAProcessFilterMap     KABPFMapName     = "ka_ea_process_filter_map"
	KAEAProcessFilterMapFile KABPFObjFileName = "ka_ea_process.bpf.o"

	KAEAEventMap     KABPFMapName     = "ka_ea_event_map"
	KAEAEventMapFile KABPFObjFileName = "ka_ea_event_map.bpf.o"

	KAEAEventFilterMap     KABPFMapName     = "ka_ea_event_filter_map"
	KAEAEventFilterMapFile KABPFObjFileName = "ka_ea_event_filter_map.bpf.o"

	KAEAEventJumpTable     KABPFMapName     = "ka_ea_event_jmp_table"
	KAEAEventJumpTableFile KABPFObjFileName = "ka_ea_event_jmp_table.bpf.o"
)

// KAEAGetMap Function
func KAEAGetMap(name KABPFMapName) KABPFMap {
	switch name {
	case KAEAPatternMap:
		return KABPFMap{
			Name:     KAEAPatternMap,
			FileName: KAEAPatternMapFile,
		}
	case KAEAProcessSpecMap:
		return KABPFMap{
			Name:     KAEAProcessSpecMap,
			FileName: KAEAProcessSpecMapFile,
		}
	case KAEAProcessFilterMap:
		return KABPFMap{
			Name:     KAEAProcessFilterMap,
			FileName: KAEAProcessFilterMapFile,
		}
	case KAEAEventMap:
		return KABPFMap{
			Name:     KAEAEventMap,
			FileName: KAEAEventMapFile,
		}
	case KAEAEventFilterMap:
		return KABPFMap{
			Name:     KAEAEventFilterMap,
			FileName: KAEAEventFilterMapFile,
		}
	case KAEAEventJumpTable:
		return KABPFMap{
			Name:     KAEAEventJumpTable,
			FileName: KAEAEventJumpTableFile,
		}
	default:
		return KABPFMap{
			Name:     "",
			FileName: "",
		}
	}
}

// =========================== //
// ======= Pattern Map ======= //
// =========================== //

// PatternMaxLen constant
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
	PatternID uint32
}

// SetKey Function (PatternMapElement)
func (pme *PatternMapElement) SetKey(pattern string) {
	copy(pme.Key.Pattern[:PatternMaxLen], pattern)
	pme.Key.Pattern[PatternMaxLen-1] = 0
}

// SetValue Function (PatternMapElement)
func (pme *PatternMapElement) SetValue(patternID uint32) {
	pme.Value.PatternID = patternID
}

// SetFoundValue Function (PatternMapElement)
func (pme *PatternMapElement) SetFoundValue(value []byte) {
	pme.Value.PatternID = binary.LittleEndian.Uint32(value)
}

// KeyPointer Function (PatternMapElement)
func (pme *PatternMapElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Key)
}

// ValuePointer Function (PatternMapElement)
func (pme *PatternMapElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pme.Value)
}

// MapName Function (PatternMapElement)
func (pme *PatternMapElement) MapName() string {
	return string(KAEAPatternMap)
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
	PatternID uint32
}

// ProcessSpecValue Structure
type ProcessSpecValue struct {
	Inspect bool
}

// SetKey Function (ProcessSpecElement)
func (pse *ProcessSpecElement) SetKey(pidNS, mntNS, patternID uint32) {
	pse.Key.PidNS = pidNS
	pse.Key.MntNS = mntNS
	pse.Key.PatternID = patternID
}

// SetValue Function (ProcessSpecElement)
func (pse *ProcessSpecElement) SetValue(inspect bool) {
	pse.Value.Inspect = inspect
}

// SetFoundValue Function (ProcessSpecElement)
func (pse *ProcessSpecElement) SetFoundValue(value []byte) {
	pse.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

// KeyPointer Function (ProcessSpecElement)
func (pse *ProcessSpecElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Key)
}

// ValuePointer Function (ProcessSpecElement)
func (pse *ProcessSpecElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pse.Value)
}

// MapName Function (ProcessSpecElement)
func (pse *ProcessSpecElement) MapName() string {
	return string(KAEAProcessSpecMap)
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

// SetKey Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) SetKey(pidNS, mntNS, hostPID uint32) {
	pfe.Key.PidNS = pidNS
	pfe.Key.MntNS = mntNS
	pfe.Key.HostPID = hostPID
}

// SetValue Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) SetValue(inspect bool) {
	pfe.Value.Inspect = inspect
}

// SetFoundValue Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) SetFoundValue(value []byte) {
	pfe.Value.Inspect = binary.LittleEndian.Uint32(value) != 0
}

// KeyPointer Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Key)
}

// ValuePointer Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&pfe.Value)
}

// MapName Function (ProcessFilterElement)
func (pfe *ProcessFilterElement) MapName() string {
	return string(KAEAProcessFilterMap)
}

// ==================== //
// ===  Event Map  ==== //
// ==================== //

// EventElement Structure
type EventElement struct {
	Key   uint32
	Value uint32
}

// SetKey Function (EventFilterElement)
func (ee *EventElement) SetKey(eventID uint32) {
	ee.Key = eventID
}

// SetValue Function (EventElement)
func (ee *EventElement) SetValue(flag uint32) {
	ee.Value = flag
}

// SetFoundValue Function (PatternMapElement)
func (ee *EventElement) SetFoundValue(value []byte) {
	ee.Value = binary.LittleEndian.Uint32(value)
}

// KeyPointer Function (EventElement)
func (ee *EventElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&ee.Key)
}

// ValuePointer Function (EventElement)
func (ee *EventElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&ee.Value)
}

// MapName Function (EventElement)
func (ee *EventElement) MapName() string {
	return string(KAEAEventMap)
}

// =========================== //
// ===  Event Filter Map  ==== //
// =========================== //

// EventFilterElement Structure
type EventFilterElement struct {
	Key   EventFilterKey
	Value EventFilterValue
}

// EventFilterKey Structure
type EventFilterKey struct {
	PidNS   uint32
	MntNS   uint32
	EventID uint32
}

// EventFilterValue Structure
type EventFilterValue struct {
	JumpIdx uint32
}

// SetKey Function (EventFilterElement)
func (efe *EventFilterElement) SetKey(pidNS, mntNS, eventID uint32) {
	efe.Key.PidNS = pidNS
	efe.Key.MntNS = mntNS
	efe.Key.EventID = eventID
}

// SetValue Function (EventFilterElement)
func (efe *EventFilterElement) SetValue(jumpIdx uint32) {
	efe.Value.JumpIdx = jumpIdx
}

// KeyPointer Function (EventFilterElement)
func (efe *EventFilterElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&efe.Key)
}

// ValuePointer Function (EventFilterElement)
func (efe *EventFilterElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&efe.Value)
}

// MapName Function (EventFilterElement)
func (efe *EventFilterElement) MapName() string {
	return string(KAEAEventFilterMap)
}

// =========================== //
// ===  Event Jump Table  ==== //
// =========================== //

// EventJumpTableElement Structure
type EventJumpTableElement struct {
	JumpIdx uint32
	ProgFD  uint32
}

// SetKey Function (EventJumpTableElement)
func (ejte *EventJumpTableElement) SetKey(jumpIdx uint32) {
	ejte.JumpIdx = jumpIdx
}

// SetValue Function (EventJumpTableElement)
func (ejte *EventJumpTableElement) SetValue(progFd uint32) {
	ejte.ProgFD = progFd
}

// KeyPointer Function (EventJumpTableElement)
func (ejte *EventJumpTableElement) KeyPointer() unsafe.Pointer {
	return unsafe.Pointer(&ejte.JumpIdx)
}

// ValuePointer Function (EventJumpTableElement)
func (ejte *EventJumpTableElement) ValuePointer() unsafe.Pointer {
	return unsafe.Pointer(&ejte.ProgFD)
}

// MapName Function (EventJumpTableElement)
func (ejte *EventJumpTableElement) MapName() string {
	return string(KAEAEventJumpTable)
}
