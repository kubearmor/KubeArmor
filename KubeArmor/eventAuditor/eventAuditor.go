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

	// entrypoints list
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	// initialize process maps and functions
	if !ea.InitializeProcessMaps() {
		ea.Logger.Err("Failed to initialize process maps")
	}

	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	// destroy deployed entrypoints
	if !ea.DestroyEntrypoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process maps and functions
	if !ea.DestroyProcessMaps() {
		ea.Logger.Err("Failed to destroy process maps")
	}

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
