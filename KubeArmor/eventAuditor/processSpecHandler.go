// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

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
		var pjmp ProcessJMPElement
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

// updatePatternMap Function
func (ea *EventAuditor) updatePatternMap(patterns map[PatternElement]bool) {
	// Delete removed elements from bpf pattern map
	for p := range ea.Patterns {
		if _, ok := patterns[p]; !ok {
			if err := ea.BPFManager.MapDeleteElement(&p); err != nil {
				ea.Logger.Warn(err.Error())
			}
			delete(ea.Patterns, p)
			continue
		}
		delete(patterns, p)
	}

	// Insert new elements into bpf pattern map
	for p := range patterns {
		if err := ea.BPFManager.MapUpdateElement(&p); err != nil {
			ea.Logger.Warn(err.Error())
		}
		ea.Patterns[p] = true
	}
}

// updateProcessSpecMap Function
func (ea *EventAuditor) updateProcessSpecMap(procSpecs map[ProcessSpecElement]bool) {
	// Delete removed elements from bpf process spec map
	for ps := range ea.ProcessSpecs {
		if _, ok := procSpecs[ps]; !ok {
			if err := ea.BPFManager.MapDeleteElement(&ps); err != nil {
				ea.Logger.Warn(err.Error())
			}
			delete(ea.ProcessSpecs, ps)
			continue
		}
		delete(procSpecs, ps)
	}

	// Insert new elements into bpf process spec map
	for ps := range procSpecs {
		if err := ea.BPFManager.MapUpdateElement(&ps); err != nil {
			ea.Logger.Warn(err.Error())
		}
		ea.ProcessSpecs[ps] = true
	}
}

// getProcessElements Function
func (ea *EventAuditor) getProcessElements() (map[PatternElement]bool, map[ProcessSpecElement]bool) {

	Containers := *(ea.Containers)
	EndPoints := *(ea.EndPoints)

	patterns := map[PatternElement]bool{}
	procSpecs := map[ProcessSpecElement]bool{}

	// Populate bpf pattern and process specs elements
	// extracting data from current audit policies
	for _, ep := range EndPoints {
		for _, cnID := range ep.Containers {
			cn := Containers[cnID]

			if cn.EndPointName != ep.EndPointName {
				continue
			}

			for _, auditPolicy := range ep.AuditPolicies {
				for _, event := range auditPolicy.Events {
					for _, path := range strings.Split(event.Path, ",") {
						p := PatternElement{}

						p.SetKey(path)
						hashID := fnv.New32()
						if _, err := hashID.Write(p.Key.Pattern[:]); err != nil {
							ea.Logger.Err(err.Error())
						}
						p.SetValue(hashID.Sum32())

						patterns[p] = true

						ps := ProcessSpecElement{}

						ps.SetKey(cn.PidNS, cn.MntNS, p.Value.PatternID)
						ps.SetValue(true)

						procSpecs[ps] = true
					}
				}
			}
		}
	}

	return patterns, procSpecs
}

// UpdateProcessMaps Function
func (ea *EventAuditor) UpdateProcessMaps() {
	ContainersLock := *(ea.ContainersLock)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	EndPointsLock := *(ea.EndPointsLock)

	EndPointsLock.Lock()
	defer EndPointsLock.Unlock()

	patterns, procSpecs := ea.getProcessElements()

	ea.updatePatternMap(patterns)
	ea.updateProcessSpecMap(procSpecs)
}
