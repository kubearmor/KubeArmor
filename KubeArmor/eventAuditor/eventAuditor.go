// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

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

	// map
	SharedMapMan *SharedMapManager

	// entrypoints list
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
	}

	// initialize process maps and functions
	ea.SharedMapMan = NewSharedMapManager()
	ea.SharedMapMan.SetBPFObjPath(BPFObjRelPath)

	if !ea.InitializeProcessMaps(ea.SharedMapMan) {
		ea.Logger.Err("Failed to initialize process maps")
	}

	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	// destroy deployed entrypoints
	if !ea.DestoryEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process maps
	if !ea.DestroyProcessMaps(ea.SharedMapMan) {
		ea.Logger.Err("Failed to destroy process maps")
	}

	ea.SharedMapMan = nil

	return nil
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
