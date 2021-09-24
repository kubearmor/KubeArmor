// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import "C"

import (
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	lbpf "github.com/kubearmor/libbpf"
)

// ===================== //
// == Const. Variables == //
// ===================== //

// System Call Numbers
const (
	SysOpen   = 2
	SysOpenAt = 257
	SysClose  = 3

	SysSocket  = 41
	SysConnect = 42
	SysAccept  = 43
	SysBind    = 49
	SysListen  = 50

	SysExecve   = 59
	SysExecveAt = 322
	DoExit      = 351
)

// =========================== //
// == Entrypoint Management == //
// =========================== //

// InitializeEntryPoints Function
func (ea *EventAuditor) InitializeEntryPoints() bool {
	var err error

	if ea.BPFManager == nil {
		return false
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventMap: %v", err)
		return false
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventFilterMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventFilterMap: %v", err)
		goto fail1
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventJumpTable), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventJumpTable: %v", err)
		goto fail2
	}

	if ea.EntryPointBPF, err = lbpf.OpenObjectFromFile("./BPF/objs/entrypoint.bpf.o"); err != nil {
		ea.Logger.Errf("Failed to open entrypoint bpf: %v", err)
		goto fail3
	}

	if err := ea.EntryPointBPF.Load(); err != nil {
		ea.Logger.Errf("Failed to load entrypoint bpf: %v", err)
		goto fail3
	}

	ea.SupportedEntryPoints = []string{
		"SYS_EXECVE", "SYS_EXECVEAT",
		"SYS_OPEN", "SYS_OPENAT",
		"SYS_SOCKET", "SYS_BIND", "SYS_LISTEN", "SYS_ACCEPT", "SYS_CONNECT"}

	for _, probe := range ea.SupportedEntryPoints {

		for _, probe := range ea.SupportedEntryPoints {
			ea.AttachEntryPoint(probe)
		}

		_, err = ea.EntryPointBPF.FindProgramByName("kprobe__sys_execve")
		if err != nil {
			ea.Logger.Errf("Failed to find entrypoint from entrypoint bpf: %v", err)
			return false
		}

		if _, err := ea.EntryPointProg.AttachKprobe(probe); err != nil {
			ea.Logger.Errf("Failed to attach kprobe (%s): %v", probe, err)
		}

		// Defining probe_id from the defined syscall numbers
		// TODO add probe_id for other syscall
		var probe_id uint32

		if probe == "SYS_OPEN" {
			probe_id = SysOpen
		}

		var eventMapElem EventElement
		eventMapElem.SetKey(probe_id)
		eventMapElem.SetValue(0)
		err = ea.BPFManager.MapUpdateElement(&eventMapElem)
	}
	return true

fail3:
	_ = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventJumpTable))

fail2:
	_ = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventFilterMap))

fail1:
	_ = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventMap))

	return false
}

// DestroyEntryPoints Function
func (ea *EventAuditor) DestroyEntryPoints() bool {
	if ea.BPFManager == nil {
		return false
	}

	// TODO: remove entrypoint bpf

	ea.EntryPointBPF.Close()

	if err := ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventJumpTable)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventJumpTable: %v", err)
	}

	if err := ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventFilterMap)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventFilterMap: %v", err)
	}

	if err := ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventMap)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventFilterMap: %v", err)
	}

	return true
}

func (ea *EventAuditor) AttachEntryPoint(probe string) {
	var eventMapElem EventElement
	eventMapElem.SetKey(SysOpen)
	eventMapElem.SetValue(1)
	err = ea.BPFManager.MapUpdateElement(&eventMapElem)
}

func (ea *EventAuditor) DetachEntryPoint(probe string) {
	var eventMapElem EventElement
	eventMapElem.SetKey(probe_id)
	eventMapElem.SetValue(0)
	err = ea.BPFManager.MapUpdateElement(&eventMapElem)
}

// UpdateEntryPoints Function
func (ea *EventAuditor) UpdateEntryPoints(auditPolicies *map[string]tp.AuditPolicy, auditPoliciesLock **sync.RWMutex) {
	AuditPolicies := *(auditPolicies)
	AuditPoliciesLock := *(auditPoliciesLock)

	AuditPoliciesLock.Lock()
	defer AuditPoliciesLock.Unlock()

	entrypointList := []string{}

	// all entrypoints list
	for _, policy := range AuditPolicies {
		for _, event := range policy.Events {
			if !kl.ContainsElement(entrypointList, event.Probe) {
				entrypointList = append(entrypointList, event.Probe)
			}
		}
	}

	newEntryPointList := []string{}

	// new entrypoints to be attached
	for _, newProbe := range entrypointList {
		if !kl.ContainsElement(ea.ActiveEntryPoints, newProbe) {
			newEntryPointList = append(newEntryPointList, newProbe)
		}
	}

	// update entrypoints
	for _, probe := range newEntryPointList {
		ea.AttachEntryPoint(probe)
	}

	oldEntrypointList := []string{}

	// old entrypoints to be detached
	for _, oldProbe := range ea.ActiveEntryPoints {
		if !kl.ContainsElement(entrypointList, oldProbe) {
			oldEntrypointList = append(oldEntrypointList, oldProbe)
		}
	}

	// update entrypoints
	for _, probe := range oldEntrypointList {
		ea.DetachEntryPoint(probe)
	}

	// replace old list with new list
	ea.ActiveEntryPoints = entrypointList
}
