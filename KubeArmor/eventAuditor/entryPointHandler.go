// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventauditor

import (
	"sync"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// =========================== //
// == Entrypoint Management == //
// =========================== //

// InitializeEntryPoints Function
func (ea *EventAuditor) InitializeEntryPoints() bool {
	// if something wrong, return false

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
	//
}

// DetachEntryPoint Function
func (ea *EventAuditor) DetachEntryPoint(probe string) {
	//
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
