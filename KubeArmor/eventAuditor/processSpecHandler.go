package eventauditor

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"sync"
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
func (ea *EventAuditor) UpdateProcessMaps(auditPolicies *map[string]tp.KubeArmorAuditPolicy,
	auditPoliciesLock **sync.RWMutex) {
	// update process-spec and pattern maps
}
