// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package monitor is the component responsible for monitoring syscalls and communicating with eBPF Programs
package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cle "github.com/cilium/ebpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// SystemMonitor Constant Values
const (
	PermissionDenied = -13
	MaxStringLen     = 4096
	PinPath          = "/sys/fs/bpf"
	visibilityOff    = uint32(1)
	visibilityOn     = uint32(0)
	// how many event the channel can hold
	SyscallChannelSize   = 1 << 13 //8192
	DefaultVisibilityKey = uint32(0xc0ffee)
)

// ======================= //
// == Namespace Context == //
// ======================= //

// NsKey Structure
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// NsVisibility Structure
type NsVisibility struct {
	NsKeys     []NsKey
	File       bool
	Process    bool
	Capability bool
	Network    bool
}

// ===================== //
// == Syscall Context == //
// ===================== //

// SyscallContext Structure
type SyscallContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32
	Argnum  int32
	Retval  int64

	Comm [16]byte
	Cwd  [80]byte
	TTY  [64]byte
	OID  uint32
}

// ContextCombined Structure
type ContextCombined struct {
	ContainerID string
	ContextSys  SyscallContext
	ContextArgs []interface{}
}

// ======================= //
// == Container Monitor == //
// ======================= //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// SystemMonitor Structure
type SystemMonitor struct {
	// node
	Node     *tp.Node
	NodeLock **sync.RWMutex

	// logs
	Logger *fd.Feeder

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// container id -> host pid
	ActiveHostPidMap *map[string]tp.PidMap
	ActivePidMapLock **sync.RWMutex

	// PidID + MntID -> container id
	NsMap     map[NsKey]string
	NsMapLock *sync.RWMutex

	// system monitor
	BpfModule            *cle.Collection
	BpfConfigMap         *cle.Map
	BpfNsVisibilityMap   *cle.Map
	BpfVisibilityMapSpec cle.MapSpec

	NsVisibilityMap  map[NsKey]*cle.Map
	NamespacePidsMap map[string]NsVisibility
	BpfMapLock       *sync.RWMutex
	PinPath          string

	// Probes Links
	Probes map[string]link.Link

	// context + args
	ContextChan chan ContextCombined

	// system events
	SyscallChannel chan []byte
	SyscallPerfMap *perf.Reader

	// lists to skip
	UntrackedNamespaces []string

	execLogMap     map[uint32]tp.Log
	execLogMapLock *sync.RWMutex
	// monitor lock
	MonitorLock **sync.RWMutex

	Status          bool
	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder
}

// NewSystemMonitor Function
func NewSystemMonitor(node *tp.Node, nodeLock **sync.RWMutex, logger *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex, monitorLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.Node = node
	mon.NodeLock = nodeLock
	mon.Logger = logger

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActiveHostPidMap = activeHostPidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.NsMap = make(map[NsKey]string)
	mon.NsMapLock = new(sync.RWMutex)

	mon.ContextChan = make(chan ContextCombined, 4096)

	mon.MonitorLock = monitorLock

	mon.Status = true
	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = binary.LittleEndian

	mon.execLogMap = map[uint32]tp.Log{}
	mon.execLogMapLock = new(sync.RWMutex)

	mon.BpfMapLock = new(sync.RWMutex)
	mon.NsVisibilityMap = make(map[NsKey]*cle.Map)
	mon.NamespacePidsMap = make(map[string]NsVisibility)
	mon.BpfVisibilityMapSpec = cle.MapSpec{
		Type:       cle.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	}

	// assign the value of untracked ns from GlobalCfg
	mon.UntrackedNamespaces = make([]string, len(cfg.GlobalCfg.ConfigUntrackedNs))
	copy(mon.UntrackedNamespaces, cfg.GlobalCfg.ConfigUntrackedNs)

	kl.CheckOrMountBPFFs(cfg.GlobalCfg.BPFFsPath)
	mon.PinPath = kl.GetMapRoot()

	return mon
}

// InitBPFMaps Function
func (mon *SystemMonitor) initBPFMaps() error {
	visibilityMap, errviz := cle.NewMapWithOptions(
		&cle.MapSpec{
			Name:       "kubearmor_visibility",
			Type:       cle.HashOfMaps,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: 65535,
			Pinning:    cle.PinByName,
			InnerMap:   &mon.BpfVisibilityMapSpec,
		}, cle.MapOptions{
			PinPath: mon.PinPath,
		})
	mon.BpfNsVisibilityMap = visibilityMap
	mon.UpdateVisibility()

	bpfConfigMap, errconfig := cle.NewMapWithOptions(
		&cle.MapSpec{
			Name:       "kubearmor_config",
			Type:       cle.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 16,
			Pinning:    cle.PinByName,
			InnerMap:   &mon.BpfVisibilityMapSpec,
		}, cle.MapOptions{
			PinPath: mon.PinPath,
		})
	mon.BpfConfigMap = bpfConfigMap
	if cfg.GlobalCfg.HostPolicy {
		if err := mon.BpfConfigMap.Update(uint32(0), uint32(1), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable host visbility : %s", err.Error())
		}
	}
	if cfg.GlobalCfg.Policy {
		if err := mon.BpfConfigMap.Update(uint32(1), uint32(1), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable container visbility : %s", err.Error())
		}
	}

	mon.UpdateThrottlingConfig()

	return errors.Join(errviz, errconfig)
}

// DestroyBPFMaps Function
func (mon *SystemMonitor) DestroyBPFMaps() {
	if mon.BpfNsVisibilityMap != nil {
		err := mon.BpfNsVisibilityMap.Unpin()
		if err != nil {
			mon.Logger.Warnf("error unpinning bpf map kubearmor_visibility %v", err)
		}
		err = mon.BpfNsVisibilityMap.Close()
		if err != nil {
			mon.Logger.Warnf("error closing bpf map kubearmor_visibility %v", err)
		}
	}

	if mon.BpfConfigMap != nil {
		err := mon.BpfConfigMap.Unpin()
		if err != nil {
			mon.Logger.Warnf("error unpinning bpf map kubearmor_config %v", err)
		}
		err = mon.BpfConfigMap.Close()
		if err != nil {
			mon.Logger.Warnf("error closing bpf map kubearmor_config %v", err)
		}
	}
}

func (mon *SystemMonitor) UpdateThrottlingConfig() {
	if cfg.GlobalCfg.AlertThrottling {
		if err := mon.BpfConfigMap.Update(uint32(3), uint32(1), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable alert throttling : %s", err.Error())
		}
	} else {
		if err := mon.BpfConfigMap.Update(uint32(3), uint32(0), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable alert throttling : %s", err.Error())
		}
	}
	if err := mon.BpfConfigMap.Update(uint32(4), uint32(cfg.GlobalCfg.MaxAlertPerSec), cle.UpdateAny); err != nil {
		mon.Logger.Errf("Error Updating System Monitor Config Map to set max alerts per sec : %s", err.Error())
	}
	if err := mon.BpfConfigMap.Update(uint32(5), uint32(cfg.GlobalCfg.ThrottleSec), cle.UpdateAny); err != nil {
		mon.Logger.Errf("Error Updating System Monitor Config Map to set time interval for dropping subsequent alerts : %s", err.Error())
	}
	mon.Logger.Printf("Alert Throttling configured {alertThrottling:%v, maxAlertPerSec:%v, throttleSec:%v}",
		cfg.GlobalCfg.AlertThrottling,
		cfg.GlobalCfg.MaxAlertPerSec,
		cfg.GlobalCfg.ThrottleSec)
}

// UpdateNsKeyMap Function
func (mon *SystemMonitor) UpdateNsKeyMap(action string, nsKey NsKey, visibility tp.Visibility) {
	var err error

	file := cle.MapKV{
		Key:   uint32(0),
		Value: visibilityOff,
	}
	process := cle.MapKV{
		Key:   uint32(1),
		Value: visibilityOff,
	}
	network := cle.MapKV{
		Key:   uint32(2),
		Value: visibilityOff,
	}
	capability := cle.MapKV{
		Key:   uint32(3),
		Value: visibilityOff,
	}
	if visibility.File {
		file.Value = visibilityOn
	}
	if visibility.Process {
		process.Value = visibilityOn
	}
	if visibility.Capabilities {
		capability.Value = visibilityOn
	}
	if visibility.Network {
		network.Value = visibilityOn
	}

	if action == "ADDED" {
		spec := mon.BpfVisibilityMapSpec
		spec.Contents = append(spec.Contents, file)
		spec.Contents = append(spec.Contents, process)
		spec.Contents = append(spec.Contents, network)
		spec.Contents = append(spec.Contents, capability)
		visibilityMap, err := cle.NewMap(&spec)
		if err != nil {
			mon.Logger.Warnf("Cannot create bpf map %s", err)
			return
		}
		mon.NsVisibilityMap[nsKey] = visibilityMap
		err = mon.BpfNsVisibilityMap.Put(nsKey, visibilityMap)
		if err != nil {
			mon.Logger.Warnf("Cannot insert insert visibility map into kernel nskey=%+v, error=%s", nsKey, err)
		}
		mon.Logger.Printf("Successfully added visibility map with key=%+v to the kernel", nsKey)
	} else if action == "MODIFIED" {
		visibilityMap := mon.NsVisibilityMap[nsKey]
		if visibilityMap == nil {
			mon.Logger.Warnf("Cannot locate visibility map. nskey=%+v, action=modified", nsKey)
			return
		}

		err = visibilityMap.Put(file.Key, file.Value)
		if err != nil {
			mon.Logger.Warnf("Cannot update visibility map. nskey=%+v, value=%+v, scope=file", nsKey, file.Value)
		}
		err = visibilityMap.Put(process.Key, process.Value)
		if err != nil {
			mon.Logger.Warnf("Cannot update visibility map. nskey=%+v, value=%+v, scope=process", nsKey, process.Value)
		}
		err = visibilityMap.Put(network.Key, network.Value)
		if err != nil {
			mon.Logger.Warnf("Cannot update visibility map. nskey=%+v, value=%+v, scope=network", nsKey, network.Value)
		}
		err = visibilityMap.Put(capability.Key, capability.Value)
		if err != nil {
			mon.Logger.Warnf("Cannot update visibility map. nskey=%+v, value=%+v, scope=capability", nsKey, capability.Value)
		}

		// Need to lock NsMap to print the following log message
		mon.NsMapLock.RLock()
		mon.Logger.Printf("Updated visibility map with key=%+v for cid %s", nsKey, mon.NsMap[nsKey])
		mon.NsMapLock.RUnlock()
	} else if action == "DELETED" {
		err := mon.BpfNsVisibilityMap.Delete(nsKey)
		if err != nil {
			mon.Logger.Warnf("Cannot locate visibility map. nskey=%+v, action=deleted", nsKey)
			return
		}
		delete(mon.NsVisibilityMap, nsKey)
		mon.Logger.Printf("Successfully deleted visibility map with key=%+v from the kernel", nsKey)
	}
}

// UpdateVisibility Function updates host visibility and global default visibility map based on the global config
func (mon *SystemMonitor) UpdateVisibility() {
	hostNSKey := NsKey{
		PidNS: 0,
		MntNS: 0,
	}

	hostVisibility := tp.Visibility{}
	if cfg.GlobalCfg.HostPolicy {
		visibilityParams := cfg.GlobalCfg.HostVisibility
		if strings.Contains(visibilityParams, "file") {
			hostVisibility.File = true
		}
		if strings.Contains(visibilityParams, "process") {
			hostVisibility.Process = true
		}
		if strings.Contains(visibilityParams, "network") {
			hostVisibility.Network = true
		}
		if strings.Contains(visibilityParams, "capabilities") {
			hostVisibility.Capabilities = true
		}
	}

	nsKey := NsKey{
		PidNS: DefaultVisibilityKey,
		MntNS: DefaultVisibilityKey,
	}

	visibility := tp.Visibility{}
	{
		visibilityParams := cfg.GlobalCfg.Visibility
		if strings.Contains(visibilityParams, "file") {
			visibility.File = true
		}
		if strings.Contains(visibilityParams, "process") {
			visibility.Process = true
		}
		if strings.Contains(visibilityParams, "network") {
			visibility.Network = true
		}
		if strings.Contains(visibilityParams, "capabilities") {
			visibility.Capabilities = true
		}
	}

	mon.BpfMapLock.Lock()
	defer mon.BpfMapLock.Unlock()
	mon.UpdateNsKeyMap("ADDED", hostNSKey, hostVisibility)
	mon.UpdateNsKeyMap("ADDED", nsKey, visibility)
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF() error {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	bpfPath := homeDir + "/BPF/"
	if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
		// go test

		bpfPath = os.Getenv("PWD") + "/../BPF/"
		if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
			// container

			bpfPath = "/opt/kubearmor/BPF/"
			if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
				return err
			}
		}
	}

	mon.Logger.Print("Initializing eBPF system monitor")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error removing memlock %v", err)
	}

	bpfPath = bpfPath + "system_monitor.bpf.o"

	err = mon.initBPFMaps()
	if err != nil {
		return err
	}
	mon.Logger.Printf("eBPF system monitor object file path: %s", bpfPath)
	bpfModuleSpec, err := cle.LoadCollectionSpec(bpfPath)
	if err != nil {
		return fmt.Errorf("cannot load bpf module specs %v", err)
	}
	mon.BpfModule, err = cle.NewCollectionWithOptions(
		bpfModuleSpec,
		cle.CollectionOptions{
			Maps: cle.MapOptions{
				PinPath: PinPath,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("bpf module is nil %v", err)
	}

	mon.Logger.Print("Initialized the eBPF system monitor")

	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "accept", "bind", "listen", "unlink", "unlinkat", "rmdir", "ptrace", "chown", "setuid", "setgid", "fchownat", "mount", "umount"}
	// {category, event}
	sysTracepoints := [][2]string{{"syscalls", "sys_exit_openat"}}
	sysKprobes := []string{"do_exit", "security_bprm_check", "security_file_open", "security_path_mknod", "security_path_unlink", "security_path_rmdir", "security_ptrace_access_check"}
	netSyscalls := []string{"tcp_connect"}
	netRetSyscalls := []string{"inet_csk_accept", "tcp_connect"}

	if mon.BpfModule != nil {

		mon.Probes = make(map[string]link.Link)

		for _, syscallName := range systemCalls {
			mon.Probes["kprobe__"+syscallName], err = link.Kprobe("sys_"+syscallName, mon.BpfModule.Programs["kprobe__"+syscallName], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", syscallName, err)
			}

			mon.Probes["kretprobe__"+syscallName], err = link.Kretprobe("sys_"+syscallName, mon.BpfModule.Programs["kretprobe__"+syscallName], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kretprobe %s: %v", syscallName, err)
			}

		}

		for _, sysTracepoint := range sysTracepoints {
			mon.Probes[sysTracepoint[1]], err = link.Tracepoint(sysTracepoint[0], sysTracepoint[1], mon.BpfModule.Programs[sysTracepoint[1]], nil)
			if err != nil {
				mon.Logger.Warnf("error:%s: %v", sysTracepoint, err)
			}
		}

		for _, sysKprobe := range sysKprobes {
			mon.Probes["kprobe__"+sysKprobe], err = link.Kprobe(sysKprobe, mon.BpfModule.Programs["kprobe__"+sysKprobe], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", sysKprobe, err)
			}
		}

		for _, netSyscall := range netSyscalls {
			mon.Probes["kprobe__"+netSyscall], err = link.Kprobe(netSyscall, mon.BpfModule.Programs["kprobe__"+netSyscall], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", netSyscall, err)
			}
		}

		for _, netRetSyscall := range netRetSyscalls {
			mon.Probes["kretprobe__"+netRetSyscall], err = link.Kretprobe(netRetSyscall, mon.BpfModule.Programs["kretprobe__"+netRetSyscall], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kretprobe %s: %v", netRetSyscall, err)
			}
		}

		mon.SyscallChannel = make(chan []byte, SyscallChannelSize)

		mon.SyscallPerfMap, err = perf.NewReader(mon.BpfModule.Maps["sys_events"], os.Getpagesize()*1024)
		if err != nil {
			mon.Logger.Warnf("error initializing events perf map: %v", err)
		}
	}

	return nil
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {

	(*mon.MonitorLock).Lock()
	defer (*mon.MonitorLock).Unlock()

	mon.Status = false

	if mon.SyscallPerfMap != nil {
		if err := mon.SyscallPerfMap.Close(); err != nil {
			return err
		}
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	for _, link := range mon.Probes {
		if err := link.Close(); err != nil {
			return err
		}
	}

	mon.DestroyBPFMaps()
	return nil
}

// ======================= //
// == System Call Trace == //
// ======================= //

// TraceSyscall Function
func (mon *SystemMonitor) TraceSyscall() {
	if mon.SyscallPerfMap != nil {
		go func() {
			for {
				record, err := mon.SyscallPerfMap.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						// This should only happen when we call DestroyMonitor while terminating the process.
						// Adding a Warn just in case it happens at runtime, to help debug
						mon.Logger.Warnf("Perf Buffer closed, exiting TraceSyscall %s", err.Error())
						return
					}
					mon.Logger.Warnf("Perf Event Error : %s", err.Error())
				}

				if record.LostSamples != 0 {
					mon.Logger.Warnf("Lost Perf Events Count : %d", record.LostSamples)
					continue
				}
				mon.SyscallChannel <- record.RawSample

			}
		}()
	} else {
		mon.Logger.Err("Perf Buffer nil, exiting TraceSyscall")
		return
	}

	Containers := *(mon.Containers)
	ContainersLock := *(mon.ContainersLock)

	ReplayChannel := make(chan []byte, SyscallChannelSize)

	go func() {
		for {
			dataRaw, valid := <-ReplayChannel
			if !valid {
				continue
			}
			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				continue
			}

			now := time.Now()
			if now.After(time.Unix(int64(ctx.Ts), 0).Add(10 * time.Second)) {
				mon.Logger.Debug("Event dropped due to replay timeout")
				continue
			}

			// Best effort replay
			go func() {
				for i := 0; i < 10; i++ {
					containerID := ""

					if ctx.PidID != 0 && ctx.MntID != 0 {
						containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID)

						if containerID == "" {
							time.Sleep(1 * time.Second)
							continue
						}
					}

					select {
					case mon.SyscallChannel <- dataRaw:
					default:
						// channel is full, wait for a short time before retrying
						time.Sleep(1 * time.Second)
						mon.Logger.Warn("Event droped due to busy event channel")
					}

				}
				mon.Logger.Debug("Event dropped due to replay timeout")
			}()
		}
	}()
	MonitorLock := *(mon.MonitorLock)

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.SyscallChannel:
			if !valid {
				mon.Logger.Debug("Invalid telemtry")
				continue
			}

			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				mon.Logger.Debugf("Error while reading context in telemetry %s", err.Error())

				continue
			}
			if ctx.PPID == ctx.HostPPID {
				ctx.PPID = 0
			}
			args, err := GetArgs(dataBuff, ctx.Argnum)
			if err != nil {
				mon.Logger.Debugf("could not fetch args so dropping %s", err.Error())
				continue
			}
			containerID := ""

			if ctx.PidID != 0 && ctx.MntID != 0 {
				containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID)

				if containerID != "" {
					ContainersLock.RLock()
					namespace := Containers[containerID].NamespaceName
					if kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
						ContainersLock.RUnlock()
						continue
					}
					ContainersLock.RUnlock()
				}
			}

			if ctx.PidID != 0 && ctx.MntID != 0 && containerID == "" {
				ReplayChannel <- dataRaw
				continue
			}

			if ctx.EventID == SysOpen {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysOpenAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysUnlink {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysUnlinkAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysRmdir {
				if len(args) != 1 {
					continue
				}
			} else if ctx.EventID == SysPtrace {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysChown {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysFChownAt {
				if len(args) != 5 {
					continue
				}
			} else if ctx.EventID == SysSetuid {
				if len(args) != 1 {
					continue
				}
			} else if ctx.EventID == SysSetgid {
				if len(args) != 1 {
					continue
				}
			} else if ctx.EventID == SysMount {
				if len(args) != 5 {
					continue
				}
			} else if ctx.EventID == SysUmount {
				if len(args) != 2 {
					continue
				}

			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					var execPath string
					var nodeArgs []string

					if val, ok := args[0].(string); ok {
						execPath = val
					}
					if val, ok := args[1].([]string); ok {
						nodeArgs = val
					}

					// generate a log with the base information
					log := mon.BuildLogBase(ctx.EventID, ContextCombined{ContainerID: containerID, ContextSys: ctx}, false)

					// fallback logic: in case we get relative path as execPath then we join cwd + execPath to get pull path
					if !strings.HasPrefix(strings.Split(execPath, " ")[0], "/") && log.Cwd != "/" {
						execPath = filepath.Join(log.Cwd, execPath)
					}

					// build a pid node
					pidNode := mon.BuildPidNode(containerID, ctx, execPath, nodeArgs, false)
					mon.AddActivePid(containerID, pidNode)

					// add arguments
					log.Resource = execPath
					if pidNode.Args != "" {
						log.Resource = log.Resource + " " + pidNode.Args
					}

					log.Operation = "Process"
					log.Data = "syscall=" + GetSyscallName(int32(ctx.EventID))

					// store the log in the map
					mon.execLogMapLock.Lock()
					mon.execLogMap[ctx.HostPID] = log
					mon.execLogMapLock.Unlock()

				} else if len(args) == 0 { // return

					// get the stored log
					mon.execLogMapLock.Lock()
					log := mon.execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(mon.execLogMap, ctx.HostPID)
					mon.execLogMapLock.Unlock()

					// update the log again
					log = mon.UpdateLogBase(ctx, log)

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == SysExecveAt {
				if len(args) == 4 { // enter
					var execPath string

					// generate a log with the base information
					log := mon.BuildLogBase(ctx.EventID, ContextCombined{ContainerID: containerID, ContextSys: ctx}, false)

					if val, ok := args[1].(string); ok {
						execPath = val // procExecPath
					}
					// fallback logic: in case we get relative path in execPath then we join cwd + execPath to get pull path
					if !strings.HasPrefix(strings.Split(execPath, " ")[0], "/") && log.Cwd != "/" {
						execPath = filepath.Join(log.Cwd, execPath)
					}

					// build a pid node
					args_2 := []string{}
					switch v := args[2].(type) {
					case []string:
						args_2 = append(args_2, v...)
					case string:
						args_2 = append(args_2, v)
					default:
						mon.Logger.Warnf("Unexpected args[2] type")
					}
					pidNode := mon.BuildPidNode(containerID, ctx, execPath, args_2, false)
					mon.AddActivePid(containerID, pidNode)

					fd := ""
					procExecFlag := ""

					// add arguments
					if val, ok := args[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					log.Resource = execPath
					if val, ok := args[2].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}
					if val, ok := args[3].(string); ok {
						procExecFlag = val
					}

					log.Operation = "Process"
					log.Data = "syscall=" + GetSyscallName(int32(ctx.EventID)) + " fd=" + fd + " flag=" + procExecFlag

					// store the log in the map
					mon.execLogMapLock.Lock()
					mon.execLogMap[ctx.HostPID] = log
					mon.execLogMapLock.Unlock()

				} else if len(args) == 0 { // return

					// get the stored log
					mon.execLogMapLock.Lock()
					log := mon.execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(mon.execLogMap, ctx.HostPID)
					mon.execLogMapLock.Unlock()

					// update the log again
					log = mon.UpdateLogBase(ctx, log)

					// get error message
					if ctx.Retval < 0 {
						message := getErrorMessage(ctx.Retval)
						if message != "" {
							log.Result = message
						} else {
							log.Result = fmt.Sprintf("Unknown (%d)", ctx.Retval)
						}
					} else {
						log.Result = "Passed"
					}

					// push the generated log
					if mon.Logger != nil {
						go mon.Logger.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == DoExit {
				mon.DeleteActivePid(containerID, ctx)
				continue
			} else if ctx.EventID == SecurityBprmCheck {
				if val, ok := args[0].(string); ok {
					mon.UpdateExecPath(containerID, ctx.HostPID, val)
				}
				continue
			} else if ctx.EventID == TCPConnect {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == TCPAccept {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == TCPConnectv6 {
				if len(args) != 2 {
					continue
				}
			}
			MonitorLock.Lock()
			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}
			MonitorLock.Unlock()
		}
	}
}
