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

	// entrypoints list
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	// initialize ebpf manager
	ea.BPFManager = NewKABPFManager()
	ea.BPFManager.SetObjsMapsPath("./BPF/objs")
	ea.BPFManager.SetObjsProgsPath("./BPF/objs")

	if err := ea.InitializeProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process maps: %v", err)
	}

	if err := ea.InitializeProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process programs: %v", err)
	}

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
	}

	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	var err error

	// destroy deployed entrypoints
	if !ea.DestroyEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process programs
	if err = ea.DestroyProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to destroy process programs: %v", err)
	}

	// destroy process maps
	if err = ea.DestroyProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to destroy process maps: %v", err)
	}

	ea.BPFManager = nil
	ea.Logger = nil

	return err
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
