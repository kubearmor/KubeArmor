package eventauditor

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"sync"
)

// =========================== //
// == Entrypoint Management == //
// =========================== //

// UpdateEntrypoints Function
func (ea *EventAuditor) UpdateEntrypoints(auditPolicies *map[string]tp.KubeArmorAuditPolicy,
	auditPoliciesLock **sync.RWMutex) {
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

// DestroyEntrypoints Function
func (ea *EventAuditor) DestroyEntrypoints() bool {
	// destroy entrypoints (from tail to head)

	return true
}
