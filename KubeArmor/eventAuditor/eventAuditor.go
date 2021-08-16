// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventauditor

import (
	"sync"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// =================== //
// == Event Auditor == //
// =================== //

// EventAuditor Structure
type EventAuditor struct {
	// logs
	Logger *fd.Feeder

	// audit policies
	AuditPolicies     *[]tp.KubeArmorAuditPolicy
	AuditPoliciesLock **sync.RWMutex
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder, auditPolicies *[]tp.KubeArmorAuditPolicy, auditPoliciesLock **sync.RWMutex) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	ea.AuditPolicies = auditPolicies
	ea.AuditPoliciesLock = auditPoliciesLock

	return ea
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	return nil
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

// UpdateAuditPolicies Function
func (ea *EventAuditor) UpdateAuditPolicies() { // (action string, auditPolicy yyy, ...)
	// update audit policies

	// call "entrypoint management"
	// call "shared map management"
}
