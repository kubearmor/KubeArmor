// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// =================== //
// == Event Auditor == //
// =================== //

// EventAuditor Structure
type EventAuditor struct {
	// logs
	Logger *fd.Feeder

	// bpf
	BPFManager *KABPFManager

	// all entrypoints that KubeArmor supports
	SupportedEntryPoints map[string]uint32

	// all entrypoints in the audit policy
	ActiveEntryPoints []string

	Patterns     map[PatternMapElement]bool
	ProcessSpecs map[ProcessSpecElement]bool
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder
	ea.Patterns = map[PatternMapElement]bool{}
	ea.ProcessSpecs = map[ProcessSpecElement]bool{}

	// initialize ebpf manager
	ea.BPFManager = NewKABPFManager()

	if err := ea.BPFManager.SetObjsMapsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf maps path: %v", err)
		return nil
	}

	if err := ea.BPFManager.SetObjsProgsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf programs path: %v", err)
		return nil
	}

	if err := ea.InitializeProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process maps: %v", err)
		return nil
	}

	if err := ea.InitializeProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process programs: %v", err)
		goto fail1
	}

	if err := ea.PopulateProcessJMPMap(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to populate process jmp map: %v", err)
		return nil
	}

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
		goto fail2
	}

	return ea

fail2:
	// destroy process programs
	_ = ea.DestroyProcessPrograms(ea.BPFManager)
fail1:
	// destroy process maps
	_ = ea.DestroyProcessMaps(ea.BPFManager)

	return nil
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	// destroy entrypoints
	if !ea.DestroyEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process programs
	err1 := ea.DestroyProcessPrograms(ea.BPFManager)
	if err1 != nil {
		ea.Logger.Errf("Failed to destroy process programs: %v", err1)
	}

	// destroy process maps
	err2 := ea.DestroyProcessMaps(ea.BPFManager)
	if err2 != nil {
		ea.Logger.Errf("Failed to destroy process maps: %v", err2)
	}

	ea.BPFManager = nil
	ea.Logger = nil

	return AppendErrors(err1, err2)
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

// func (ea *EventAuditor) GenerateAuditPrograms() {
// 	//
// }

// func (ea *EventAuditor) ChainAuditPrograms() {
// 	//
// }
