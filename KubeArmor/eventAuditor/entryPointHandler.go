// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"
	"sync"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	bpf "github.com/kubearmor/libbpf"
)

// =========================== //
// == Entrypoint Management == //
// =========================== //

// InitializeEventMaps Function
func (ea *EventAuditor) InitializeEventMaps(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	err1 := bman.InitMap(KAEAGetMap(KAEAEventFilterMap), true)
	err2 := bman.InitMap(KAEAGetMap(KAEAEventJumpTable), true)

	return AppendErrors(err1, err2)
}

// DestroyEventMaps Function
func (ea *EventAuditor) DestroyEventMaps(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	err1 := bman.DestroyMap(KAEAGetMap(KAEAEventFilterMap))
	err2 := bman.DestroyMap(KAEAGetMap(KAEAEventJumpTable))

	return AppendErrors(err1, err2)
}

// InitializeEntryPoints Function
func (ea *EventAuditor) InitializeEntryPoints() bool {
	// if something wrong, return false
	b, err := bpf.OpenObjectFromFile("entrypoint.bpf.o")
	must(err)
	defer b.Close()

	err = b.Load()
	must(err)

	return true
}

// DestroyEntryPoints Function
func (ea *EventAuditor) DestroyEntryPoints() bool {
	// if something wrong, return false

	// destroy entrypoints (from tail to head)

	return true
}

// AttachEntryPoint Function
func (ea *EventAuditor) AttachEntryPoint(probe string) {
	prog, err := b.FindProgramByName(entrypoint)
	must(err)
	_, err = prog.AttachKprobe(sys_execve)
	must(err)
}

// DetachEntryPoint Function
func (ea *EventAuditor) DetachEntryPoint(probe string) {
	// TODO
}

// UpdateEntryPoints Function
func (ea *EventAuditor) UpdateEntryPoints(auditPolicies *map[string]tp.AuditPolicy, auditPoliciesLock **sync.RWMutex) {
	// AuditPolicies := *(auditPolicies)
	// AuditPoliciesLock := *(auditPoliciesLock)

	// AuditPoliciesLock.Lock()
	// defer AuditPoliciesLock.Unlock()

	// new entrypoints list
	// for _, policy := range AuditPolicies {
	//     append probe to new entrypoints list
	// }

	// outdated entrypoints
	// for _, probe := range entrypoints-list {
	// if probe not in new entrypoints-list, append it to outdated entrypoints
	// }

	// replace old entrypoints list with new entrypoints list

	// update (attach/detach) entrypoints (ebpf)
}
