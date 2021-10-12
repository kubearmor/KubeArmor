// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"fmt"
	"os"
	"strings"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
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

	// bpf
	BPFManager *KABPFManager

	// all entrypoints that KubeArmor supports
	SupportedEntryPoints map[string]uint32

	// entrypoint arguments
	EntryPointParameters map[string][]string

	// all entrypoints in the audit policy
	ActiveEntryPoints []string

	// patterns and process specs
	Patterns     map[PatternElement]bool
	ProcessSpecs map[ProcessSpecElement]bool

	// cache for compiled rules
	// map[eventString]codeBlock
	EventCodeBlockCache map[string]string

	// cache for loaded programs
	// map[sourceCode]jumpTableIndex
	EventProgramCache map[string]uint32

	// next index to use
	NextJumpTableIndex uint32

	// lock for caches and index count
	CacheIndexLock *sync.RWMutex
}

// SaveRuntimeInfo Function
func (ea *EventAuditor) SaveRuntimeInfo() error {
	var err error
	var file *os.File

	if file, err = os.Create("./BPF/runtime.h"); err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("// SPDX-License-Identifier: GPL-2.0\n")
	file.WriteString("// Copyright 2021 Authors of KubeArmor\n\n")

	file.WriteString("#ifndef u64\n")
	file.WriteString("typedef unsigned long long u64;\n")
	file.WriteString("#endif\n\n")

	file.WriteString("u64 __bpf_pseudo_fd(u64, u64) asm(\"llvm.bpf.pseudo\");\n")
	file.WriteString("#define __ka_ea_map(fd) __bpf_pseudo_fd(1, fd)\n\n")

	file.WriteString(fmt.Sprintf("#define ka_ea_process_jmp_map    %d\n",
		ea.BPFManager.getMap(KAEAProcessJMPMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_pattern_map        %d\n",
		ea.BPFManager.getMap(KAEAPatternMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_process_spec_map   %d\n",
		ea.BPFManager.getMap(KAEAProcessSpecMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_process_filter_map %d\n",
		ea.BPFManager.getMap(KAEAProcessFilterMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_event_map          %d\n",
		ea.BPFManager.getMap(KAEAEventMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_event_filter_map   %d\n",
		ea.BPFManager.getMap(KAEAEventFilterMap).FD()))

	file.WriteString(fmt.Sprintf("#define ka_ea_event_jmp_table    %d\n",
		ea.BPFManager.getMap(KAEAEventJumpTable).FD()))

	return nil
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	// initialize ebpf manager
	ea.BPFManager = NewKABPFManager()

	// initialize maps for patterns and process specs
	ea.Patterns = map[PatternElement]bool{}
	ea.ProcessSpecs = map[ProcessSpecElement]bool{}

	// initialize caches
	ea.EventCodeBlockCache = make(map[string]string)
	ea.EventProgramCache = make(map[string]uint32)

	ea.NextJumpTableIndex = 0
	ea.CacheIndexLock = new(sync.RWMutex)

	if err := ea.BPFManager.SetObjsMapsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf maps path: %v", err)
		return nil
	}

	if err := ea.BPFManager.SetObjsProgsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf programs path: %v", err)
		return nil
	}

	if err := ea.InitializeProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process maps: %v", err)
		return nil
	}

	if err := ea.InitializeProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process programs: %v", err)
		goto fail1
	}

	if err := ea.PopulateProcessJMPMap(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to populate process jmp map: %v", err)
		return nil
	}

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
		goto fail2
	}

	if err := ea.SaveRuntimeInfo(); err != nil {
		ea.Logger.Errf("Failed to create runtime.h: %v", err)
		goto fail2
	}

	return ea

fail2:
	// destroy process programs
	_ = ea.DestroyProcessPrograms(ea.BPFManager)
fail1:
	// destroy process maps
	_ = ea.DestroyProcessMaps(ea.BPFManager)

	return nil
}

// DestroyEventAuditor Function
func (ea *EventAuditor) DestroyEventAuditor() error {
	// destroy entrypoints
	if !ea.DestroyEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	// destroy process programs
	err1 := ea.DestroyProcessPrograms(ea.BPFManager)
	if err1 != nil {
		ea.Logger.Errf("Failed to destroy process programs: %v", err1)
	}

	// destroy process maps
	err2 := ea.DestroyProcessMaps(ea.BPFManager)
	if err2 != nil {
		ea.Logger.Errf("Failed to destroy process maps: %v", err2)
	}

	ea.BPFManager = nil
	ea.Logger = nil

	return AppendErrors(err1, err2)
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

// UpdateAuditPrograms Function
func (ea *EventAuditor) UpdateAuditPrograms(endPoints []tp.EndPoint, endPointsLock *sync.RWMutex, containers map[string]tp.Container) {
	var eventFilterElement EventFilterElement

	endPointsLock.Lock()
	defer endPointsLock.Unlock()

	getEventID := func(probe string) uint32 {
		if strings.HasPrefix(probe, "sys_") {
			probe = strings.Split(probe, "sys_")[1]
		}

		return ea.SupportedEntryPoints[probe]
	}

	for _, ep := range endPoints {
		progCodeBlocks := make(map[string][]string)
		progLoaded := make(map[uint32]uint32)

		if len(ep.AuditPolicies) == 0 {
			continue
		}

		// generate the event code blocks
		for _, auditPolicy := range ep.AuditPolicies {
			for _, eventRule := range auditPolicy.Events {
				if codeBlock, err := ea.GenerateCodeBlock(eventRule); err == nil {
					if !kl.ContainsElement(progCodeBlocks[eventRule.Probe], codeBlock) {
						current := progCodeBlocks[eventRule.Probe]
						progCodeBlocks[eventRule.Probe] = append(current, codeBlock)
					}
				} else {
					ea.Logger.Warnf("Failed to generate audit code: %v", err)
				}
			}
		}

		// generate and load the event programs
		for probe, codeBlocks := range progCodeBlocks {
			source := ea.GenerateAuditProgram(probe, codeBlocks)
			eventID := getEventID(probe)

			if index, err := ea.LoadAuditProgram(source, probe); err == nil {
				progLoaded[eventID] = index
			} else {
				ea.Logger.Errf("Failed to load audit program: %v", err)
			}
		}

		// populate ka_ea_event_filter_map
		for _, containerName := range ep.Containers {
			pidns := containers[containerName].PidNS
			mntns := containers[containerName].MntNS

			for eventID, jmpTableIndex := range progLoaded {
				eventFilterElement.SetKey(pidns, mntns, eventID)
				eventFilterElement.SetValue(jmpTableIndex)
				if err := ea.BPFManager.MapUpdateElement(&eventFilterElement); err != nil {
					ea.Logger.Errf("Failed to update ka_ea_event_filter_map: eventID=%d, jmpTableIndex=%d",
						eventID, jmpTableIndex)
				}
			}
		}
	}
}
