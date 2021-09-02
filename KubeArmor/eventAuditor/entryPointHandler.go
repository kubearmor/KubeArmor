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
	// TODO Detach function is not implemented yet
	prog, err := b.FindProgramByName(entrypoint)
	must(err)
	_, err = prog.Detach(sys_execve)
	must(err)
}

// Contains the list of all entrypoints in the audit policy
EntrypointList := []string

// UpdateEntryPoints Function
func (ea *EventAuditor) UpdateEntryPoints(auditPolicies *map[string]tp.AuditPolicy,
	  auditPoliciesLock **sync.RWMutex) {
	AuditPolicies := *(auditPolicies)
	AuditPoliciesLock := *(auditPoliciesLock)

	AuditPoliciesLock.Lock()
	defer AuditPoliciesLock.Unlock()


	// new entrypoints list
	for _, policy := range AuditPolicies {
		for i, event := range Events {
			NewEntrypointList = append(NewList, Events.Probe[i])
		}

	// outdated entrypoints, it will be in the toBeDetached array
	for _, entrypoint := range EntrypointList {
		for _, probe := range EntrypointList {
			if (probe != EntrypointList)
			{
				OldEntrypointList = append(OldEntrypointList, probe)
			}
		}
	}

	// replace old entrypoints list with new entrypoints list
	EntrypointList := NewEntrypointList

	// update (attach/detach) entrypoints (ebpf)
	for _, probe := range NewEntrypointList {
		AttachEntryPoint(probe)
	}

	for _, probe := range OldEntrypointList {
		DetachEntryPoint(probe)
	}

}
