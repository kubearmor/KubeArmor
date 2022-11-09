// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package monitor is the component responsible for monitoring syscalls and communicating with eBPF Programs
package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

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
)

// ======================= //
// == Namespace Context == //
// ======================= //

// NsKey Structure
type NsKey struct {
	PidNS uint32
	MntNS uint32
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
	Node *tp.Node

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

	// system monitor (for container)
	BpfModule *cle.Collection

	// Probes Links
	Probes map[string]link.Link

	// context + args
	ContextChan chan ContextCombined

	// system events
	SyscallChannel chan []byte
	SyscallPerfMap *perf.Reader

	// lists to skip
	UntrackedNamespaces []string

	Status          bool
	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder
}

// NewSystemMonitor Function
func NewSystemMonitor(node *tp.Node, logger *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.Node = node
	mon.Logger = logger

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActiveHostPidMap = activeHostPidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.NsMap = make(map[NsKey]string)
	mon.NsMapLock = new(sync.RWMutex)

	mon.ContextChan = make(chan ContextCombined, 4096)

	mon.UntrackedNamespaces = []string{"kube-system", "kubearmor"}

	mon.Status = true
	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = binary.LittleEndian

	return mon
}

func loadIgnoreList(bpfPath string) ([]string, error) {

	ignoreListName := bpfPath + "ignore.lst"
	if _, err := os.Stat(filepath.Clean(ignoreListName)); err != nil {
		return []string{}, nil
	}

	file, err := os.Open(filepath.Clean(ignoreListName))
	if err != nil {
		return []string{}, err
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	ignoreList := []string{}
	for scanner.Scan() {
		ignoreList = append(ignoreList, scanner.Text()[1:])
	}

	if err := file.Close(); err != nil {
		return []string{}, err
	}

	return ignoreList, nil
}

var syscallsInKernelFeatureFlag = map[string][]string{
	"DSECURITY_PATH": {
		"security_path_unlink",
		"security_path_rmdir",
	},
}

func isIgnored(item string, ignoreList []string) bool {
	for _, ignoreFlag := range ignoreList {
		for _, syscall := range syscallsInKernelFeatureFlag[ignoreFlag] {
			if syscall == item {
				return true
			}
		}
	}
	return false
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

	ignoreList, err := loadIgnoreList(bpfPath)
	if err != nil {
		return err
	}

	mon.Logger.Print("Initializing eBPF system monitor")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error removing memlock %v", err)
	}

	if cfg.GlobalCfg.Policy && !cfg.GlobalCfg.HostPolicy { // container only
		bpfPath = bpfPath + "system_monitor.container.bpf.o"
	} else if !cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy { // host only
		bpfPath = bpfPath + "system_monitor.host.bpf.o"
	} else if cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy { // container and host
		bpfPath = bpfPath + "system_monitor.bpf.o"
	}
	mon.Logger.Printf("eBPF system monitor object file path: %s", bpfPath)
	mon.BpfModule, err = cle.LoadCollection(bpfPath)
	if err != nil {
		return fmt.Errorf("bpf module is nil %v", err)
	}

	mon.Logger.Print("Initialized the eBPF system monitor")

	// sysPrefix := bcc.GetSyscallPrefix()
	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "accept", "bind", "listen", "unlink", "unlinkat", "rmdir", "chown", "setuid", "setgid", "fchownat"}
	// {category, event}
	sysTracepoints := [][2]string{{"syscalls", "sys_exit_openat"}}
	sysKprobes := []string{"do_exit", "security_bprm_check", "security_file_open", "security_path_unlink", "security_path_rmdir"}
	netSyscalls := []string{"tcp_connect"}
	netRetSyscalls := []string{"inet_csk_accept"}

	if mon.BpfModule != nil {

		mon.Probes = make(map[string]link.Link)

		for _, syscallName := range systemCalls {
			if isIgnored(syscallName, ignoreList) {
				mon.Logger.Printf("Ignoring syscall %s", syscallName)
				continue
			}
			mon.Probes["kprobe__"+syscallName], err = link.Kprobe("sys_"+syscallName, mon.BpfModule.Programs["kprobe__"+syscallName], nil)
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}

			mon.Probes["kretprobe__"+syscallName], err = link.Kretprobe("sys_"+syscallName, mon.BpfModule.Programs["kretprobe__"+syscallName], nil)
			if err != nil {
				return fmt.Errorf("error loading kretprobe %s: %v", syscallName, err)
			}

		}

		for _, sysTracepoint := range sysTracepoints {
			mon.Probes[sysTracepoint[1]], err = link.Tracepoint(sysTracepoint[0], sysTracepoint[1], mon.BpfModule.Programs[sysTracepoint[1]], nil)
			if err != nil {
				return fmt.Errorf("error:%s: %v", sysTracepoint, err)
			}
		}

		for _, sysKprobe := range sysKprobes {
			if isIgnored(sysKprobe, ignoreList) {
				mon.Logger.Printf("Ignoring kprobe %s", sysKprobe)
				continue
			}
			mon.Probes["kprobe__"+sysKprobe], err = link.Kprobe(sysKprobe, mon.BpfModule.Programs["kprobe__"+sysKprobe], nil)
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", sysKprobe, err)
			}
		}

		for _, netSyscall := range netSyscalls {
			if isIgnored(netSyscall, ignoreList) {
				mon.Logger.Printf("Ignoring syscall %s", netSyscall)
				continue
			}
			mon.Probes["kprobe__"+netSyscall], err = link.Kprobe(netSyscall, mon.BpfModule.Programs["kprobe__"+netSyscall], nil)
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", netSyscall, err)
			}
		}

		for _, netRetSyscall := range netRetSyscalls {
			if isIgnored(netRetSyscall, ignoreList) {
				mon.Logger.Printf("Ignoring syscall %s", netRetSyscall)
				continue
			}
			mon.Probes["kretprobe__"+netRetSyscall], err = link.Kretprobe(netRetSyscall, mon.BpfModule.Programs["kretprobe__"+netRetSyscall], nil)
			if err != nil {
				return fmt.Errorf("error loading kretprobe %s: %v", netRetSyscall, err)
			}
		}

		mon.SyscallChannel = make(chan []byte, 8192)

		mon.SyscallPerfMap, err = perf.NewReader(mon.BpfModule.Maps["sys_events"], os.Getpagesize()*1024)
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	return nil
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {
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
					continue
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

	execLogMap := map[uint32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.SyscallChannel:
			if !valid {
				continue
			}

			dataBuff := bytes.NewBuffer(dataRaw)
			ctx, err := readContextFromBuff(dataBuff)
			if err != nil {
				continue
			}
			args, err := GetArgs(dataBuff, ctx.Argnum)
			if err != nil {
				continue
			}
			containerID := ""

			if ctx.PidID != 0 && ctx.MntID != 0 {
				containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID, ctx.HostPPID, ctx.HostPID)

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
				continue
			}

			// if Policy is not set
			if !cfg.GlobalCfg.Policy && containerID != "" {
				continue
			}

			// if HostPolicy is not set
			if !cfg.GlobalCfg.HostPolicy && containerID == "" {
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

			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode(containerID, ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid(containerID, pidNode)

					// if Policy is not set
					if !cfg.GlobalCfg.Policy && containerID != "" {
						continue
					}

					// if HostPolicy is not set
					if !cfg.GlobalCfg.HostPolicy && containerID == "" {
						continue
					}

					// generate a log with the base information
					log := mon.BuildLogBase(ctx.EventID, ContextCombined{ContainerID: containerID, ContextSys: ctx})

					// add arguments
					if val, ok := args[0].(string); ok {
						log.Resource = val // procExecPath
					}
					if val, ok := args[1].([]string); ok {
						for idx, arg := range val { // procArgs
							if idx == 0 {
								continue
							} else {
								log.Resource = log.Resource + " " + arg
							}
						}
					}

					log.Operation = "Process"
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID))

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// if Policy is not set
					if !cfg.GlobalCfg.Policy && containerID != "" {
						continue
					}

					// if HostPolicy is not set
					if !cfg.GlobalCfg.HostPolicy && containerID == "" {
						continue
					}

					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					log = mon.UpdateLogBase(ctx.EventID, log)

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
					// build a pid node
					pidNode := mon.BuildPidNode(containerID, ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(containerID, pidNode)

					// if Policy is not set
					if !cfg.GlobalCfg.Policy && containerID != "" {
						continue
					}

					// if HostPolicy is not set
					if !cfg.GlobalCfg.HostPolicy && containerID == "" {
						continue
					}

					// generate a log with the base information
					log := mon.BuildLogBase(ctx.EventID, ContextCombined{ContainerID: containerID, ContextSys: ctx})

					fd := ""
					procExecFlag := ""

					// add arguments
					if val, ok := args[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := args[1].(string); ok {
						log.Resource = val // procExecPath
					}
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
					log.Data = "syscall=" + getSyscallName(int32(ctx.EventID)) + " fd=" + fd + " flag=" + procExecFlag

					// store the log in the map
					execLogMap[ctx.HostPID] = log

				} else if len(args) == 0 { // return
					// if Policy is not set
					if !cfg.GlobalCfg.Policy && containerID != "" {
						continue
					}

					// if HostPolicy is not set
					if !cfg.GlobalCfg.HostPolicy && containerID == "" {
						continue
					}

					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

					// update the log again
					log = mon.UpdateLogBase(ctx.EventID, log)

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

			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}
		}
	}
}
