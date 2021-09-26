// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"
	"fmt"
	"sync"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	lbpf "github.com/kubearmor/libbpf"
)

// ============================= //
// == Process Spec Management == //
// ============================= //

// InitializeProcessMaps Function
func (ea *EventAuditor) InitializeProcessMaps(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	// create (pin) global maps
	err1 := bman.InitMap(KAEAGetMap(KAEAProcessJMPMap), true)
	err2 := bman.InitMap(KAEAGetMap(KAEAPatternMap), true)
	err3 := bman.InitMap(KAEAGetMap(KAEAProcessSpecMap), true)
	err4 := bman.InitMap(KAEAGetMap(KAEAProcessFilterMap), true)

	return AppendErrors(err1, err2, err3, err4)
}

// PopulateProcessJMPMap Function
func (ea *EventAuditor) PopulateProcessJMPMap(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	var p *lbpf.KABPFProgram
	var err error

	if p = bman.getProg(KAEASysExecveProg); p == nil {
		return fmt.Errorf("program %v not initialized", KAEASysExecveProg)
	}

	for _, tp := range KAEAGetProg(KAEASysExecveProg).TailProgs {
		var pjmp ProcessJMPMapElement
		var tailProg *lbpf.KABPFProgram

		if tailProg, err = p.Object().FindProgramByName(string(tp.Name)); err != nil {
			return err
		}

		pjmp.Key = tp.Index
		pjmp.Value = uint32(tailProg.FD())
		err = bman.MapUpdateElement(&pjmp)
		if err != nil {
			return err
		}
	}

	return nil
}

// DestroyProcessMaps Function
func (ea *EventAuditor) DestroyProcessMaps(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	// delete (unpin) global maps
	err1 := bman.DestroyMap(KAEAGetMap(KAEAProcessFilterMap))
	err2 := bman.DestroyMap(KAEAGetMap(KAEAProcessSpecMap))
	err3 := bman.DestroyMap(KAEAGetMap(KAEAPatternMap))
	err4 := bman.DestroyMap(KAEAGetMap(KAEAProcessJMPMap))

	return AppendErrors(err1, err2, err3, err4)
}

// InitializeProcessPrograms Function
func (ea *EventAuditor) InitializeProcessPrograms(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	// attach ebpf program for process-spec, pattern, process-filter mgmt
	err1 := bman.InitProgram(KAEAGetProg(KAEASysExecveProg))
	err2 := bman.InitProgram(KAEAGetProg(KAEASysExitProg))

	err3 := bman.AttachProgram(KAEAGetProg(KAEASysExecveProg))
	err4 := bman.AttachProgram(KAEAGetProg(KAEASysExitProg))

	return AppendErrors(err1, err2, err3, err4)
}

// DestroyProcessPrograms Function
func (ea *EventAuditor) DestroyProcessPrograms(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	// detach ebpf program for process-spec, pattern, process-filter mgmt
	err1 := bman.DetachProgram(KAEAGetProg(KAEASysExecveProg))
	err2 := bman.DetachProgram(KAEAGetProg(KAEASysExitProg))

	err3 := bman.DestroyProgram(KAEAGetProg(KAEASysExecveProg))
	err4 := bman.DestroyProgram(KAEAGetProg(KAEASysExitProg))

	return AppendErrors(err1, err2, err3, err4)
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
