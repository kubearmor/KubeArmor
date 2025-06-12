// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package bpflsm is responsible for setting/cleaning up objects for BPF LSM enforcer and handle updates for the same
package bpflsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer ../../BPF/enforcer.bpf.c -- -I/usr/include/ -O2 -g -fno-stack-protector
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer_path ../../BPF/enforcer_path.bpf.c -- -I/usr/include/ -O2 -g -fno-stack-protector

// ===================== //
// == BPFLSM Enforcer == //
// ===================== //

// BPFEnforcer structure to maintains relevant objects for BPF LSM Enforcement
type BPFEnforcer struct {
	Logger *fd.Feeder

	InnerMapSpec *ebpf.MapSpec
	// InnerMapSpec            *ebpf.MapSpec
	BPFContainerMap         *ebpf.Map
	BPFContainerThrottleMap *ebpf.Map

	// events
	Events        *ringbuf.Reader
	EventsChannel chan []byte

	// ContainerID -> NsKey + rules
	ContainerMap     map[string]ContainerKV
	ContainerMapLock *sync.RWMutex

	obj     enforcerObjects
	objPath enforcer_pathObjects

	Probes map[string]link.Link

	Monitor *mon.SystemMonitor
}

// NewBPFEnforcer instantiates a objects for setting up BPF LSM Enforcement
func NewBPFEnforcer(node tp.Node, pinpath string, logger *fd.Feeder, monitor *mon.SystemMonitor) (*BPFEnforcer, error) {

	be := &BPFEnforcer{}

	be.Logger = logger
	be.Monitor = monitor

	var err error

	if err := rlimit.RemoveMemlock(); err != nil {
		be.Logger.Errf("Error removing rlimit %v", err)
		return nil, nil // Doesn't require clean up so not returning err
	}

	be.Probes = make(map[string]link.Link)
	be.ContainerMap = make(map[string]ContainerKV)
	be.ContainerMapLock = new(sync.RWMutex)

	be.InnerMapSpec = &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    512,
		ValueSize:  2,
		MaxEntries: 256,
	}

	be.BPFContainerMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		InnerMap:   be.InnerMapSpec,
		Name:       "kubearmor_containers",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		be.Logger.Errf("error creating kubearmor_containers map: %s", err)
		return be, err
	}

	be.BPFContainerThrottleMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  24,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		Name:       "kubearmor_alert_throttle",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		be.Logger.Errf("error creating kubearmor_alert_throttle map: %s", err)
		return be, err
	}

	if err := loadEnforcerObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			be.Logger.Errf("Verifier error: %+v", ve)
		}
		be.Logger.Errf("error loading BPF LSM objects: %v", err)
		return be, err
	}

	be.Probes[be.obj.EnforceProc.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceProc})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceProc.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceFile.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceFile})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceFile.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceFilePerm.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceFilePerm})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceFilePerm.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceNetCreate.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetCreate})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetCreate.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceNetConnect.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetConnect})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetConnect.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceNetAccept.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetAccept})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetAccept.String(), err)
		return be, err
	}
	be.Probes[be.obj.EnforceCap.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceCap})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceCap.String(), err)
		return be, err
	}

	/*
		Path Hooks

		Create, Link, Unlink, Symlink, Rename, MkDir, RmDir, Chown, Chmod, Truncate

		These will only work if the system has `CONFIG_SECURITY_PATH=y`

		We only warn if we fail to load the following hooks
	*/

	if err := loadEnforcer_pathObjects(&be.objPath, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: common.GetMapRoot(),
		},
	}); err != nil {
		be.Logger.Warnf("error loading BPF LSM Path objects. This usually suggests that the system doesn't have the system has `CONFIG_SECURITY_PATH=y`: %v", err)
	} else {
		be.Probes[be.objPath.EnforceMknod.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceMknod})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceMknod.String(), err)
		}

		be.Probes[be.objPath.EnforceLinkSrc.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceLinkSrc})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceLinkSrc.String(), err)
		}

		be.Probes[be.objPath.EnforceLinkDst.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceLinkDst})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceLinkDst.String(), err)
		}

		be.Probes[be.objPath.EnforceUnlink.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceUnlink})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceUnlink.String(), err)
		}

		be.Probes[be.objPath.EnforceSymlink.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceSymlink})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceSymlink.String(), err)
		}

		be.Probes[be.objPath.EnforceMkdir.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceMkdir})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceMkdir.String(), err)
		}

		be.Probes[be.objPath.EnforceChmod.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceChmod})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceChmod.String(), err)
		}

		// We do not support Chown for now because of limitations of bpf_trampoline https://github.com/iovisor/bcc/issues/3657
		// be.Probes[be.objPath.EnforceChown.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceChown})
		// if err != nil {
		// 	be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceChown.String(), err)
		// }

		be.Probes[be.objPath.EnforceTruncate.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceTruncate})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceTruncate.String(), err)
		}

		be.Probes[be.objPath.EnforceRenameNew.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRenameNew})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRenameNew.String(), err)
		}

		be.Probes[be.objPath.EnforceRenameOld.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRenameOld})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRenameOld.String(), err)
		}

		be.Probes[be.objPath.EnforceRmdir.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRmdir})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRmdir.String(), err)
		}
	}

	be.Events, err = ringbuf.NewReader(be.obj.KubearmorEvents)
	if err != nil {
		be.Logger.Errf("opening ringbuf reader: %s", err)
		return be, err
	}
	be.EventsChannel = make(chan []byte, mon.SyscallChannelSize)

	go be.TraceEvents()

	if cfg.GlobalCfg.HostPolicy {
		be.AddHostToMap()
	}

	return be, nil
}

type eventBPF struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32

	Retval int64

	Comm [80]byte

	Data InnerKey

	// exec events
	ExecID uint64
}

// TraceEvents traces events generated by bpflsm enforcer
func (be *BPFEnforcer) TraceEvents() {

	if be.Events == nil {
		be.Logger.Err("ringbuf reader is nil, exiting trace events")
	}
	be.Logger.Print("Starting TraceEvents from BPF LSM Enforcer")
	go func() {
		for {

			record, err := be.Events.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// This should only happen when we call DestroyMonitor while terminating the process.
					// Adding a Warn just in case it happens at runtime, to help debug
					be.Logger.Warnf("Ring Buffer closed, exiting TraceEvents %s", err.Error())
					return
				}
				be.Logger.Warnf("Ringbuf error reading %s", err.Error())
				continue
			}

			be.EventsChannel <- record.RawSample

		}
	}()

	for {

		dataRaw := <-be.EventsChannel

		var event eventBPF

		if err := binary.Read(bytes.NewBuffer(dataRaw), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		readLink := false
		if len(string(bytes.Trim(event.Data.Source[:], "\x00"))) == 0 {
			readLink = true
		}
		containerID := ""

		if event.PidID != 0 && event.MntID != 0 {
			containerID = be.Monitor.LookupContainerID(event.PidID, event.MntID)
		}

		log := be.Monitor.BuildLogBase(event.EventID, mon.ContextCombined{
			ContainerID: containerID,
			ContextSys: mon.SyscallContext{
				PID:  event.PID,
				PPID: event.PPID,
				UID:  event.UID,

				HostPID:  event.HostPID,
				HostPPID: event.HostPPID,
			},
		}, readLink)

		// exec event
		log.ExecEvent.ExecID = strconv.FormatUint(event.ExecID, 10)
		if comm := strings.TrimRight(string(event.Comm[:]), "\x00"); len(comm) > 0 {
			log.ExecEvent.ExecutableName = comm
		}

		switch event.EventID {

		case mon.FileOpen, mon.FilePermission, mon.FileMknod, mon.FileMkdir, mon.FileRmdir, mon.FileUnlink, mon.FileSymlink, mon.FileLink, mon.FileRename, mon.FileChmod, mon.FileTruncate:
			log.Operation = "File"
			log.Resource = string(bytes.Trim(event.Data.Path[:], "\x00"))
			log.Data = "lsm=" + mon.GetSyscallName(int32(event.EventID))

		case mon.SocketCreate, mon.SocketConnect, mon.SocketAccept:
			var sockProtocol int32
			sockProtocol = int32(event.Data.Path[1])
			log.Operation = "Network"
			if event.Data.Path[0] == 2 {
				log.Resource = fd.GetProtocolFromType(int32(event.Data.Path[1]))
			} else if event.Data.Path[0] == 3 {
				log.Resource = fd.GetProtocolFromName(mon.GetProtocol(sockProtocol))
			}
			log.Data = "lsm=" + mon.GetSyscallName(int32(event.EventID)) + " " + log.Resource

		case mon.SecurityBprmCheck:
			log.Operation = "Process"
			log.Resource = log.Source
			log.Source = string(bytes.Trim(event.Data.Source[:], "\x00"))
			log.ProcessName = string(bytes.Trim(event.Data.Path[:], "\x00"))
			log.ParentProcessName = log.Source
			log.Data = "lsm=" + mon.GetSyscallName(int32(event.EventID))

			// fallback logic if we don't receive resource from BuildLogBase()
			if len(log.Resource) == 0 {
				log.Resource = log.ProcessName
			}

		case mon.Capable:
			log.Operation = "Capabilities"
			log.Resource = mon.Capabilities[int32(event.Data.Path[1])]
			log.Data = "lsm=" + mon.GetSyscallName(int32(event.EventID)) + " " + log.Resource

		case mon.DropAlert:
			log.Operation = "AlertThreshold"
			log.Type = "SystemEvent"
			log.MaxAlertsPerSec = cfg.GlobalCfg.MaxAlertPerSec
			log.DroppingAlertsInterval = cfg.GlobalCfg.ThrottleSec
		}
		// fallback logic if we don't receive source from BuildLogBase()
		if log.Operation != "Process" && len(log.Source) == 0 {
			log.Source = string(bytes.Trim(event.Data.Source[:], "\x00"))
			log.ProcessName = log.Source
		}
		if len(log.ProcessName) == 0 && len(log.Source) > 0 {
			log.ProcessName = log.Source
		}
		if event.Retval >= 0 {
			log.Result = "Passed"
		} else {
			log.Result = "Permission denied"
		}
		log.Enforcer = "BPFLSM"
		be.Logger.PushLog(log)

	}
}

// UpdateSecurityPolicies loops through containers present in the input endpoint and updates rules for each container
func (be *BPFEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	for _, cid := range endPoint.Containers {
		be.Logger.Printf("Updating container rules for %s", cid)
		be.UpdateContainerRules(cid, endPoint.SecurityPolicies, endPoint.DefaultPosture)
	}

}

// UpdateHostSecurityPolicies updates rules for the host
func (be *BPFEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	be.Logger.Print("Updating host rules")
	be.UpdateHostRules(secPolicies)

}

// DestroyBPFEnforcer cleans up the objects for BPF LSM Enforcer
func (be *BPFEnforcer) DestroyBPFEnforcer() error {
	if be == nil {
		return nil
	}
	var errBPFCleanUp error

	if err := be.obj.Close(); err != nil {
		be.Logger.Err(err.Error())
		errBPFCleanUp = errors.Join(errBPFCleanUp, err)
	}

	for _, link := range be.Probes {
		if link == nil {
			continue
		}
		if err := link.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)

		}
	}

	be.ContainerMapLock.Lock()

	if be.BPFContainerMap != nil {
		if err := be.BPFContainerMap.Unpin(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
		if err := be.BPFContainerMap.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
	}

	if be.BPFContainerThrottleMap != nil {
		if err := be.BPFContainerThrottleMap.Unpin(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
		if err := be.BPFContainerThrottleMap.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
	}

	be.ContainerMapLock.Unlock()

	if be.Events != nil {
		if err := be.obj.KubearmorEvents.Unpin(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
		if err := be.obj.KubearmorEvents.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
		if err := be.Events.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = errors.Join(errBPFCleanUp, err)
		}
	}

	be = nil
	return errBPFCleanUp
}
