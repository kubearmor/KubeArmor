// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iovisor/gobpf/bcc"
	lbpf "github.com/kubearmor/libbpf"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

// System Call Numbers
const (
	SysOpen   = 2
	SysOpenAt = 257
	SysClose  = 3

	SysSocket  = 41
	SysConnect = 42
	SysAccept  = 43
	SysBind    = 49
	SysListen  = 50

	SysExecve   = 59
	SysExecveAt = 322
	DoExit      = 351
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
	// host
	HostName      string
	KernelVersion string

	// options
	EnableKubeArmorPolicy     bool
	EnableKubeArmorHostPolicy bool

	// logs
	Logger *fd.Feeder

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// container id -> (host) pid
	ActivePidMap     *map[string]tp.PidMap
	ActiveHostPidMap *map[string]tp.PidMap
	ActivePidMapLock **sync.RWMutex

	// PidID + MntID -> container id
	NsMap     map[NsKey]string
	NsMapLock *sync.RWMutex

	// system monitor (for container)
	BpfModule *lbpf.KABPFObject

	// context + args (for container)
	ContextChan chan ContextCombined

	// process + file (for container)
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *lbpf.KABPFPerfBuffer

	// host pid
	ActiveHostMap     *map[uint32]tp.PidMap
	ActiveHostMapLock **sync.RWMutex

	// system monitor (for host)
	HostBpfModule *lbpf.KABPFObject

	// context + args (for host)
	HostContextChan chan ContextCombined

	// process + file (for host)
	HostSyscallChannel     chan []byte
	HostSyscallLostChannel chan uint64
	HostSyscallPerfMap     *lbpf.KABPFPerfBuffer

	// lists to skip
	UntrackedNamespaces []string

	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder

	// ticker to clean up exited pids
	Ticker *time.Ticker

	// GKE
	IsCOS bool
}

// NewSystemMonitor Function
func NewSystemMonitor(node tp.Node, logger *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activePidMap *map[string]tp.PidMap, activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex,
	activeHostMap *map[uint32]tp.PidMap, activeHostMapLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.HostName = node.NodeName
	mon.KernelVersion = node.KernelVersion

	mon.EnableKubeArmorPolicy = node.EnableKubeArmorPolicy
	mon.EnableKubeArmorHostPolicy = node.EnableKubeArmorHostPolicy

	mon.Logger = logger

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActivePidMap = activePidMap
	mon.ActiveHostPidMap = activeHostPidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.ActiveHostMap = activeHostMap
	mon.ActiveHostMapLock = activeHostMapLock

	mon.NsMap = make(map[NsKey]string)
	mon.NsMapLock = new(sync.RWMutex)

	mon.ContextChan = make(chan ContextCombined, 4096)
	mon.HostContextChan = make(chan ContextCombined, 4096)

	mon.UntrackedNamespaces = []string{"kube-system", "kubearmor"}

	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = bcc.GetHostByteOrder()

	mon.Ticker = time.NewTicker(time.Second * 1)

	mon.IsCOS = false

	return mon
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF() error {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile(filepath.Clean("/media/root/etc/os-release")); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				mon.Logger.Print("Detected Container-Optimized OS, started to download kernel headers for COS")

				// check and download kernel headers
				if err := kl.RunCommandAndWaitWithErr(homeDir+"/GKE/download_cos_kernel_headers.sh", []string{}); err != nil {
					mon.Logger.Errf("Failed to download COS kernel headers (%s)", err.Error())
					return err
				}

				mon.Logger.Printf("Downloaded kernel headers (%s)", mon.KernelVersion)

				// set a new location for kernel headers
				if err := os.Setenv("BCC_KERNEL_SOURCE", homeDir+"/GKE/kernel/usr/src/linux-headers-"+mon.KernelVersion); err != nil {
					mon.Logger.Err(err.Error())
				}

				// just for safety
				time.Sleep(time.Second * 1)

				mon.IsCOS = true
			}
		}
	}

	bpfObjPath := homeDir + "/BPF/objs/"
	if _, err := os.Stat(filepath.Clean(bpfObjPath)); err != nil {
		// go test

		bpfObjPath = os.Getenv("PWD") + "/../BPF/objs/"
		if _, err := os.Stat(filepath.Clean(bpfObjPath)); err != nil {
			return err
		}
	}

	mon.Logger.Print("Initializing an eBPF program")

	if mon.EnableKubeArmorPolicy && !mon.EnableKubeArmorHostPolicy { // container only
		mon.BpfModule, err = lbpf.OpenObjectFromFile(bpfObjPath + "system_monitor.bpf.o")
		if err != nil {
			return fmt.Errorf("error opening the bpf object file %v", err)
		}
	} else if !mon.EnableKubeArmorPolicy && mon.EnableKubeArmorHostPolicy { // host only
		mon.HostBpfModule, err = lbpf.OpenObjectFromFile(bpfObjPath + "system_monitor_host.bpf.o")
		if err != nil {
			return fmt.Errorf("error opening the bpf object file %v", err)
		}
	} else if mon.EnableKubeArmorPolicy && mon.EnableKubeArmorHostPolicy { // container and host
		if strings.HasPrefix(mon.KernelVersion, "4.") { // 4.x
			mon.BpfModule, err = lbpf.OpenObjectFromFile(bpfObjPath + "system_monitor_host_and_container.bpf.o")
			if err != nil {
				return fmt.Errorf("error opening the bpf object file %v", err)
			}
		} else { // 5.x
			mon.BpfModule, err = lbpf.OpenObjectFromFile(bpfObjPath + "system_monitor.bpf.o")
			if err != nil {
				return fmt.Errorf("error opening the bpf object file %v", err)
			}
			mon.HostBpfModule, err = lbpf.OpenObjectFromFile(bpfObjPath + "system_monitor_host.bpf.o")
			if err != nil {
				return fmt.Errorf("error opening the bpf object file %v", err)
			}
		}
	}

	mon.Logger.Print("Initialized the eBPF program")

	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "accept", "bind", "listen"}

	if mon.BpfModule != nil {
		err = mon.BpfModule.Load()
		if err != nil {
			return fmt.Errorf("error loading the bpf object file %v", err)
		}
		for _, syscallName := range systemCalls {
			bpfProg, err := mon.BpfModule.FindProgramByName("kprobe__" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", syscallName, err)
			}
			_, err = bpfProg.AttachKprobe("__x64_sys_" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", syscallName, err)
			}
			bpfProg, err = mon.BpfModule.FindProgramByName("kretprobe__" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kretprobe %s: %v", syscallName, err)
			}
			_, err = bpfProg.AttachKretprobe("__x64_sys_" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kretprobe %s: %v", syscallName, err)
			}
		}

		kprobes := []string{"do_exit"}

		for _, kprobe := range kprobes {
			bpfProg, err := mon.BpfModule.FindProgramByName(fmt.Sprintf("kprobe__%s", kprobe))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", kprobe, err)
			}
			_, err = bpfProg.AttachKprobe(kprobe)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", kprobe, err)
			}
		}

		mon.SyscallChannel = make(chan []byte, 8192)
		mon.SyscallLostChannel = make(chan uint64)

		mon.SyscallPerfMap, err = mon.BpfModule.InitPerfBuf("sys_events", mon.SyscallChannel, mon.SyscallLostChannel, 64)
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	if mon.HostBpfModule != nil {
		for _, syscallName := range systemCalls {
			bpfProg, err := mon.HostBpfModule.FindProgramByName(fmt.Sprintf("kprobe__" + syscallName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}
			_, err = bpfProg.AttachKprobe("__x64_sys_" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", syscallName, err)
			}
			bpfProg, err = mon.HostBpfModule.FindProgramByName(fmt.Sprintf("kretprobe__" + syscallName))
			if err != nil {
				return fmt.Errorf("error loading kretprobe %s: %v", syscallName, err)
			}
			_, err = bpfProg.AttachKretprobe("__x64_sys_" + syscallName)
			if err != nil {
				return fmt.Errorf("error attaching kretprobe %s: %v", syscallName, err)
			}
		}

		kprobes := []string{"do_exit"}

		for _, kprobe := range kprobes {
			bpfProg, err := mon.HostBpfModule.FindProgramByName(fmt.Sprintf("kprobe__%s", kprobe))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", kprobe, err)
			}
			_, err = bpfProg.AttachKprobe(kprobe)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", kprobe, err)
			}
		}

		mon.HostSyscallChannel = make(chan []byte, 8192)
		mon.HostSyscallLostChannel = make(chan uint64)

		mon.HostSyscallPerfMap, err = mon.HostBpfModule.InitPerfBuf("sys_events", mon.HostSyscallChannel, mon.HostSyscallLostChannel, 64)
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	return nil
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.StopPoll()
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	if mon.HostSyscallPerfMap != nil {
		mon.HostSyscallPerfMap.StopPoll()
	}

	if mon.HostBpfModule != nil {
		mon.HostBpfModule.Close()
	}

	if mon.HostContextChan != nil {
		close(mon.HostContextChan)
	}

	mon.Ticker.Stop()

	return nil
}

// ======================= //
// == System Call Trace == //
// ======================= //

// TraceSyscall Function
func (mon *SystemMonitor) TraceSyscall() {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.StartPoll()
	} else {
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

			if ctx.EventID == SysOpen {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysOpenAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode(ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid(containerID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: containerID, ContextSys: ctx})

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
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

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
					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(containerID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: containerID, ContextSys: ctx})

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
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

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
			}

			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

		//nolint
		case <-mon.SyscallLostChannel:
			continue
		}
	}
}

// TraceHostSyscall Function
func (mon *SystemMonitor) TraceHostSyscall() {
	if mon.HostSyscallPerfMap != nil {
		mon.HostSyscallPerfMap.StartPoll()
	} else {
		return
	}

	execLogMap := map[uint32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.HostSyscallChannel:
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

			if ctx.EventID == SysOpen {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SysOpenAt {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SysExecve {
				if len(args) == 2 { // enter
					// build a pid node
					pidNode := mon.BuildPidNode(ctx, args[0].(string), args[1].([]string))
					mon.AddActiveHostPid(ctx.HostPID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: "", ContextSys: ctx})

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
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

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
					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActiveHostPid(ctx.HostPID, pidNode)

					// generate a log with the base information
					log := mon.BuildLogBase(ContextCombined{ContainerID: "", ContextSys: ctx})

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
					// get the stored log
					log := execLogMap[ctx.HostPID]

					// remove the log from the map
					delete(execLogMap, ctx.HostPID)

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
				mon.DeleteActiveHostPid(ctx.HostPID)
				continue
			}

			// push the context to the channel for logging
			mon.HostContextChan <- ContextCombined{ContainerID: "", ContextSys: ctx, ContextArgs: args}

		//nolint
		case <-mon.SyscallLostChannel:
			continue
		}
	}
}
