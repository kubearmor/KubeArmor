// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"
	"strings"

	jenkins "leb.io/hashland/jenkins"
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
	err1 := bman.InitMap(KAEAGetMap(KAEAFilenameMap), true)
	err2 := bman.InitMap(KAEAGetMap(KAEAPatternMap), true)
	err3 := bman.InitMap(KAEAGetMap(KAEAProcessSpecMap), true)
	err4 := bman.InitMap(KAEAGetMap(KAEAProcessFilterMap), true)

	return AppendErrors(err1, err2, err3, err4)
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
	err4 := bman.DestroyMap(KAEAGetMap(KAEAFilenameMap))

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

// updateFilenameMap Function
func (ea *EventAuditor) updateFilenameMap(filenames map[FilenameElement]bool) {
	// Delete removed elements from bpf filename map
	for fn := range ea.Filenames {
		if _, ok := filenames[fn]; !ok {
			if err := ea.BPFManager.MapDeleteElement(&fn); err != nil {
				ea.Logger.Warn(err.Error())
			}
			delete(ea.Filenames, fn)
			continue
		}
		delete(filenames, fn)
	}

	// Insert new elements into bpf filename map
	for fn := range filenames {
		if err := ea.BPFManager.MapUpdateElement(&fn); err != nil {
			ea.Logger.Warn(err.Error())
		}
		ea.Filenames[fn] = true
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
func (ea *EventAuditor) getProcessElements() (map[FilenameElement]bool, map[ProcessSpecElement]bool) {

	Containers := *(ea.Containers)
	EndPoints := *(ea.EndPoints)

	filenameHashes := map[FilenameElement]bool{}
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
						fne := FilenameElement{}
						hashKey, _ := jenkins.HashString(path, 0, 0)

						fne.SetKey(hashKey)
						fne.SetValue(true)

						filenameHashes[fne] = true

						ps := ProcessSpecElement{}

						ps.SetKey(cn.PidNS, cn.MntNS, fne.Key.Hash)
						ps.SetValue(true)

						procSpecs[ps] = true
					}
				}
			}
		}
	}

	return filenameHashes, procSpecs
}

// UpdateProcessMaps Function
func (ea *EventAuditor) UpdateProcessMaps() {
	ContainersLock := *(ea.ContainersLock)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	EndPointsLock := *(ea.EndPointsLock)

	EndPointsLock.Lock()
	defer EndPointsLock.Unlock()

	filenameHashes, procSpecs := ea.getProcessElements()

	ea.updateFilenameMap(filenameHashes)
	ea.updateProcessSpecMap(procSpecs)
}
