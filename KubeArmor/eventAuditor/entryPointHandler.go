// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"C"
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

// InitializeEntryPoints is used to initialize all
// data structures before handling entrypoints
func (ea *EventAuditor) InitializeEntryPoints() bool {
	b, err := bpf.OpenObjectFromFile("KubeArmor/BPF/objs/entrypoint.bpf.o")
	must(err)
	defer b.Close()

	err = b.Load()
	must(err)

	return true
}

// DestroyEntryPoints is used to clean all used dat structures
// and any changes applied to the kernel
func (ea *EventAuditor) DestroyEntryPoints() bool {

	//TODO destroy entrypoints
	Destroy()

	return true
}

func (ea *EventAuditor) AttachEntryPoint(probe string) {
	b, err := bpf.OpenObjectFromFile("KubeArmor/BPF/entrypoint.bpf.o")
	must(err)
	defer b.Close()

	prog, err := b.FindProgramByName("entrypoint")
	must(err)
	_, err = prog.AttachKprobe(sys_execve)
	must(err)
}

func (ea *EventAuditor) DetachEntryPoint(probe string) {
	b, err := bpf.OpenObjectFromFile("KubeArmor/BPF/entrypoint.bpf.o")
	must(err)
	defer b.Close()

	// TODO Detach function is not implemented yet
	prog, err := b.FindProgramByName("entrypoint")
	must(err)
	_, err = prog.Detach(sys_execve)
	must(err)
}

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
			ea.NewEntrypointList = append(ea.NewEntrypointList, Events.Probe[i])
		}
	}

	// outdated entrypoints, it will be in the OldEntrypointList array
	for _, entrypoint := range ea.EntrypointList {
		for i, probe := range ea.EntrypointList {
			if probe != ea.NewEntrypointList[i] {
				ea.OldEntrypointList = append(ea.OldEntrypointList, probe)
			}
		}
	}

	// replace old entrypoints list with new entrypoints list
	ea.EntrypointList = ea.NewEntrypointList

	// update (attach/detach) entrypoints (ebpf)
	for _, probe := range ea.NewEntrypointList {
		ea.AttachEntryPoint(probe)
	}

	for _, probe := range ea.OldEntrypointList {
		ea.DetachEntryPoint(probe)
	}

}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
