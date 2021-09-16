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

// =========================== //
// == Entrypoint Management == //
// =========================== //

// InitializeEntryPoints Function
func (ea *EventAuditor) InitializeEntryPoints() bool {
	if ea.BPFManager == nil {
		return false
	}

	if err := ea.BPFManager.InitMap(KAEAGetMap(KAEAEventMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventMap: %v", err)
		return false
	}

	if err := ea.BPFManager.InitMap(KAEAGetMap(KAEAEventFilterMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventFilterMap: %v", err)
		return false
	}

	if err := ea.BPFManager.InitMap(KAEAGetMap(KAEAEventJumpTable), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventJumpTable: %v", err)
		return false
	}

	b, err := lbpf.OpenObjectFromFile("./BPF/objs/entrypoint.bpf.o")
	if err != nil {
		ea.Logger.Errf("Failed to open entrypoint bpf: %v", err)
		return false
	}
	ea.EntryPointBPF = b

	if err := ea.EntryPointBPF.Load(); err != nil {
		ea.Logger.Errf("Failed to load entrypoint bpf: %v", err)
		return false
	}

	ea.SupportedEntryPoints = []string{
		"SYS_EXECVE", "SYS_EXECVEAT",
		"SYS_OPEN", "SYS_OPENAT",
		"SYS_SOCKET", "SYS_BIND", "SYS_LISTEN", "SYS_ACCEPT", "SYS_CONNECT"}

	// for _, probe := range ea.SupportedEntryPoints {
	// attach all entrpoints

	// p, err := ea.EntryPointBPF.FindProgramByName("entrypoint")
	// if err != nil {
	// 	ea.Logger.Errf("Failed to find entrypoint from entrypoint bpf: %v", err)
	// 	return false
	// }

	// if _, err := ea.EntryPointProg.AttachKprobe(probe); err != nil { // probe = sys_open
	// 	ea.Logger.Errf("Failed to attach kprobe (%s): %v", probe, err)
	// }

	// set KAEAEventMap[syscall_id] = 0
	// }

	return true
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
	// set KAEAEventMap[probe_id] = 1
}

func (ea *EventAuditor) DetachEntryPoint(probe string) {
	// set KAEAEventMap[probe_id] = 0
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
