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
func (ea *EventAuditor) InitializeProcessMaps(sharedMapMan *SharedMapManager) bool {
	var err error

	if sharedMapMan == nil {
		return false
	}

	// create (pin) global maps
	_, err = sharedMapMan.InitMap(KAEAPatternMap, true)
	if err != nil {
		return false
	}

	_, err = sharedMapMan.InitMap(KAEAProcessSpecMap, true)
	if err != nil {
		sharedMapMan.DestroyMap(KAEAPatternMap)
		return false
	}

	_, err = sharedMapMan.InitMap(KAEAProcessFilterMap, true)
	if err != nil {
		sharedMapMan.DestroyMap(KAEAProcessSpecMap)
		sharedMapMan.DestroyMap(KAEAPatternMap)
		return false
	}

	// attach ebpf program for process-spec, pattern, process-filter mgmt

	return true
}

// DestroyProcessMaps Function
func (ea *EventAuditor) DestroyProcessMaps(sharedMapMan *SharedMapManager) bool {
	var err error
	var ret bool

	if sharedMapMan == nil {
		return false
	}

	// detach ebpf program for process-spec, pattern, process-filter mgmt

	// delete (unpin) global maps
	err = sharedMapMan.DestroyMap(KAEAProcessFilterMap)
	ret = err == nil
	err = sharedMapMan.DestroyMap(KAEAProcessSpecMap)
	ret = ret && err == nil
	err = sharedMapMan.DestroyMap(KAEAPatternMap)
	ret = ret && err == nil

	return ret
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
