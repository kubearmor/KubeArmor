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

// KAEABuiltinMacros Definition
var KAEABuiltinMacros = map[string]string{
	// from fcntl.h
	"O_ACCMODE":      "00000003",
	"O_RDONLY":       "00000000",
	"O_WRONLY":       "00000001",
	"O_RDWR":         "00000002",
	"O_CREAT":        "00000100",
	"O_EXCL":         "00000200",
	"O_NOCTTY":       "00000400",
	"O_TRUNC":        "00001000",
	"O_APPEND":       "00002000",
	"O_NONBLOCK":     "00004000",
	"O_DSYNC":        "00010000",
	"FASYNC":         "00040000",
	"O_DIRECT":       "00000003",
	"O_LARGEFILE":    "00100000",
	"O_DIRECTORY":    "00200000",
	"O_NOFOLLOW":     "00400000",
	"O_NOATIME":      "01000000",
	"O_CLOEXEC":      "02000000",
	"O_PATH":         "010000000",
	"__O_SYNC":       "04000000",
	"O_SYNC":         "__O_SYNC | O_DSYNC",
	"__O_TMPFILE":    "020000000",
	"O_TMPFILE":      "__O_TMPFILE | O_DIRECTORY",
	"O_TMPFILE_MASK": "__O_TMPFILE | O_DIRECTORY | O_CREAT",
	"O_NDELAY":       "O_NONBLOCK",

	// from open(2) — Linux manual page
	"S_IRWXU": "00700",
	"S_IRUSR": "00400",
	"S_IWUSR": "00200",
	"S_IXUSR": "00100",
	"S_IRWXG": "00070",
	"S_IRGRP": "00040",
	"S_IWGRP": "00020",
	"S_IXGRP": "00010",
	"S_IRWXO": "00007",
	"S_IROTH": "00004",
	"S_IWOTH": "00002",
	"S_IXOTH": "00001",
	"S_ISUID": "0004000",
	"S_ISGID": "0002000",
	"S_ISVTX": "0001000",
}

// EventAuditor Structure
type EventAuditor struct {
	// logs
	Logger *fd.Feeder

	// containers
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// endpoints
	EndPoints     *[]tp.EndPoint
	EndPointsLock **sync.RWMutex

	// audit policies
	AuditPolicies     *map[string]tp.AuditPolicy
	AuditPoliciesLock **sync.RWMutex

	// == //

	// bpf
	BPFManager *KABPFManager

	// == //

	// all entrypoints that KubeArmor supports
	SupportedEntryPoints map[string]uint32

	// entrypoint arguments
	EntryPointParameters map[string][]string

	// all entrypoints in the audit policy
	ActiveEntryPoints []string

	// == //

	// filenames and process specs
	Filenames    map[FilenameElement]bool
	ProcessSpecs map[ProcessSpecElement]bool

	// == //

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

	// == //

	// next rule number to use
	NextRuleNumber uint32
	RuleNumberLock *sync.RWMutex
}

// SaveRuntimeInfo Function
func (ea *EventAuditor) SaveRuntimeInfo() error {
	var err error
	var file *os.File
	var fileContent string

	if file, err = os.Create("./BPF/runtime.h"); err != nil {
		return err
	}

	fileContent += "// SPDX-License-Identifier: GPL-2.0\n"
	fileContent += "// Copyright 2021 Authors of KubeArmor\n\n"

	fileContent += "#ifndef u64\n"
	fileContent += "typedef unsigned long long u64;\n"
	fileContent += "#endif\n\n"

	fileContent += "u64 __bpf_pseudo_fd(u64, u64) asm(\"llvm.bpf.pseudo\");\n"
	fileContent += "#define __ka_ea_map(fd) __bpf_pseudo_fd(1, fd)\n\n"

	fileContent += fmt.Sprintf("#define ka_ea_filename_map       %d\n",
		ea.BPFManager.getMap(KAEAFilenameMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_pattern_map        %d\n",
		ea.BPFManager.getMap(KAEAPatternMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_process_spec_map   %d\n",
		ea.BPFManager.getMap(KAEAProcessSpecMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_process_filter_map %d\n",
		ea.BPFManager.getMap(KAEAProcessFilterMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_event_map          %d\n",
		ea.BPFManager.getMap(KAEAEventMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_event_filter_map   %d\n",
		ea.BPFManager.getMap(KAEAEventFilterMap).FD())

	fileContent += fmt.Sprintf("#define ka_ea_event_jmp_table    %d\n",
		ea.BPFManager.getMap(KAEAEventJumpTable).FD())

	fileContent += fmt.Sprintf("#define ka_ea_ringbuff_map    %d\n",
		ea.BPFManager.getMap(KAEAEventRingBuffer).FD())

	fileContent += fmt.Sprintf("#define ka_ea_rate_limit_map     %d\n",
		ea.BPFManager.getMap(KAEAEventRateMap).FD())

	return kl.SafeFileWriteAndClose(file, fileContent)
}

// GetUniqRuleID Function
func (ea *EventAuditor) GetUniqRuleID() uint32 {
	ea.RuleNumberLock.Lock()
	defer ea.RuleNumberLock.Unlock()

	nextRuleNumber := ea.NextRuleNumber
	ea.NextRuleNumber++
	return nextRuleNumber
}

// NewEventAuditor Function
func NewEventAuditor(feeder *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	endPoints *[]tp.EndPoint, endPointsLock **sync.RWMutex, auditPolicies *map[string]tp.AuditPolicy, auditPoliciesLock **sync.RWMutex) *EventAuditor {
	ea := new(EventAuditor)

	ea.Logger = feeder

	ea.Containers = containers
	ea.ContainersLock = containersLock

	ea.EndPoints = endPoints
	ea.EndPointsLock = endPointsLock

	ea.AuditPolicies = auditPolicies
	ea.AuditPoliciesLock = auditPoliciesLock

	// == //

	// initialize ebpf manager
	ea.BPFManager = NewKABPFManager()

	if err := ea.BPFManager.SetObjsMapsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf maps path: %v", err)
		return nil
	}

	if err := ea.BPFManager.SetObjsProgsPath("./BPF/objs"); err != nil {
		ea.Logger.Errf("Failed to set ebpf programs path: %v", err)
		return nil
	}

	// == //

	// initialize entrypoints
	if !ea.InitializeEntryPoints() {
		ea.Logger.Err("Failed to initialize entrypoints")
		return nil
	}

	// == //

	// initialize maps for filenames and process specs
	ea.Filenames = map[FilenameElement]bool{}
	ea.ProcessSpecs = map[ProcessSpecElement]bool{}

	if err := ea.InitializeProcessMaps(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process maps: %v", err)
		return nil
	}

	if err := ea.InitializeProcessPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize process programs: %v", err)
		goto fail1
	}

	// == //

	// initialize caches
	ea.EventCodeBlockCache = make(map[string]string)
	ea.EventProgramCache = make(map[string]uint32)

	ea.NextJumpTableIndex = 0
	ea.CacheIndexLock = new(sync.RWMutex)

	if err := ea.SaveRuntimeInfo(); err != nil {
		ea.Logger.Errf("Failed to create runtime.h: %v", err)
		goto fail2
	}

	go ea.RingbufferConsume()

  // == //

	// initialize rule number
	ea.NextRuleNumber = 0
	ea.RuleNumberLock = new(sync.RWMutex)

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

	// destroy entrypoints
	if !ea.DestroyEntryPoints() {
		ea.Logger.Err("Failed to destroy entrypoints")
	}

	ea.BPFManager = nil
	ea.Logger = nil

	return AppendErrors(err1, err2)
}

// ============================= //
// == Audit Policy Management == //
// ============================= //

// UpdateAuditPrograms Function
func (ea *EventAuditor) UpdateAuditPrograms() {
	Containers := *(ea.Containers)
	ContainersLock := *(ea.ContainersLock)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	EndPoints := *(ea.EndPoints)
	EndPointsLock := *(ea.EndPointsLock)

	EndPointsLock.Lock()
	defer EndPointsLock.Unlock()

	var eventFilterElement EventFilterElement

	getEventID := func(probe string) uint32 {
		if strings.HasPrefix(probe, "sys_") {
			probe = strings.Split(probe, "sys_")[1]
		}

		return ea.SupportedEntryPoints[probe]
	}

	for _, ep := range EndPoints {
		progCodeBlocks := make(map[string][]string)
		progLoaded := make(map[uint32]uint32)

		if len(ep.AuditPolicies) == 0 {
			continue
		}

		// generate the event code blocks
		for _, auditPolicy := range ep.AuditPolicies {
			for uniqID, eventRule := range auditPolicy.Events {
				if codeBlock, err := ea.GenerateCodeBlock(eventRule, uniqID); err == nil {
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
			pidns := Containers[containerName].PidNS
			mntns := Containers[containerName].MntNS

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
