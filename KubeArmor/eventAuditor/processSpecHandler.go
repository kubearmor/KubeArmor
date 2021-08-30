// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventauditor

import (
	"sync"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ============================= //
// == Process Spec Management == //
// ============================= //

// InitializeProcessMaps Function
func (ea *EventAuditor) InitializeProcessMaps() bool {
	// create (pin) global maps
	// attach ebpf program for process-spec, pattern, process-filter mgmt

	return true
}

// DestroyProcessMaps Function
func (ea *EventAuditor) DestroyProcessMaps() bool {
	// detach ebpf program for process-spec, pattern, process-filter mgmt
	// delete (unpin) global maps

	return true
}

// UpdateProcessMaps Function
func (ea *EventAuditor) UpdateProcessMaps(endPoints *[]tp.EndPoint, endPointsLock **sync.RWMutex) {
	// update process-spec and pattern maps

	// for _, endPoint := range endPoints {
	// 	for _, auditPolicy := range endPoint.AuditPolicies {
	// 		//
	// 	}
	// }
}
