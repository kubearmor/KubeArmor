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

	// Contains the list of all entrypoints in the audit policy
	EntrypointList := []string

	// entrypoints list
	var NewEntrypointList []string // entrypoints to be attached
	var OldEntrypointList []string // entrypoints to be detached

	// lists to separately store probes
	var kprobes []string
	var syscalls []string
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

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

	if err := ea.InitializeEventMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize event maps: %v", err)
		goto fail2
	}

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
		goto fail3
	}

	return ea

fail3:
	_ = ea.DestroyEventMaps(ea.BPFManager)
fail2:
	_ = ea.DestroyProcessPrograms(ea.BPFManager)
fail1:
	_ = ea.DestroyProcessMaps(ea.BPFManager)

	return nil
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

	// destroy event maps
	if err = ea.DestroyEventMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to destroy event maps: %v", err)
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
