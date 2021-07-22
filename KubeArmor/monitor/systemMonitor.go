// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iovisor/gobpf/bcc"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

const (
	// file
	SYS_OPEN   = 2
	SYS_OPENAT = 257
	SYS_CLOSE  = 3

	// network
	SYS_SOCKET  = 41
	SYS_CONNECT = 42
	SYS_ACCEPT  = 43
	SYS_BIND    = 49
	SYS_LISTEN  = 50

	// process
	SYS_EXECVE   = 59
	SYS_EXECVEAT = 322
	DO_EXIT      = 351
)

const (
	PERMISSION_DENIED = -13
	MAX_STRING_LEN    = 4096
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
	// host name
	HostName string

	// logs
	LogFeeder *fd.Feeder

	// options
	EnableAuditd     bool
	EnableHostPolicy bool

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
	BpfModule *bcc.Module

	// context + args (for container)
	ContextChan chan ContextCombined

	// process + file (for container)
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *bcc.PerfMap

	// host pid
	ActiveHostMap     *map[uint32]tp.PidMap
	ActiveHostMapLock **sync.RWMutex

	// system monitor (for host)
	HostBpfModule *bcc.Module

	// context + args (for host)
	HostContextChan chan ContextCombined

	// process + file (for host)
	HostSyscallChannel     chan []byte
	HostSyscallLostChannel chan uint64
	HostSyscallPerfMap     *bcc.PerfMap

	// lists to skip
	UntrackedNamespaces []string

	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder

	// ticker to clean up exited pids
	Ticker *time.Ticker

	// GKE
	IsCOS bool

	// Kernel
	KernelVersion string
}

// NewSystemMonitor Function
func NewSystemMonitor(feeder *fd.Feeder, enableAuditd, enableHostPolicy bool,
	containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activePidMap *map[string]tp.PidMap, activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex,
	activeHostMap *map[uint32]tp.PidMap, activeHostMapLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.HostName = kl.GetHostName()

	mon.LogFeeder = feeder

	mon.EnableAuditd = enableAuditd
	mon.EnableHostPolicy = enableHostPolicy

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

	mon.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	mon.KernelVersion = strings.TrimSuffix(mon.KernelVersion, "\n")

	return mon
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF() error {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				mon.LogFeeder.Print("Detected Container-Optimized OS, started to download kernel headers for COS")

				// check and download kernel headers
				if err := exec.Command(homeDir + "/GKE/download_cos_kernel_headers.sh").Run(); err != nil {
					mon.LogFeeder.Errf("Failed to download COS kernel headers (%s)", err.Error())
					return err
				}

				mon.LogFeeder.Printf("Downloaded kernel headers (%s)", mon.KernelVersion)

				// set a new location for kernel headers
				os.Setenv("BCC_KERNEL_SOURCE", homeDir+"/GKE/kernel/usr/src/linux-headers-"+mon.KernelVersion)

				// just for safety
				time.Sleep(time.Second * 1)

				mon.IsCOS = true
			}
		}
	}

	bpfPath := homeDir + "/BPF/system_monitor.c"
	if _, err := os.Stat(bpfPath); err != nil {
		// go test

		bpfPath = os.Getenv("PWD") + "/../BPF/system_monitor.c"
		if _, err := os.Stat(bpfPath); err != nil {
			return err
		}
	}

	content, err := ioutil.ReadFile(bpfPath)
	if err != nil {
		return err
	}
	bpfSource := string(content)

	mon.LogFeeder.Print("Initializing an eBPF program")

	if mon.EnableHostPolicy {
		if strings.HasPrefix(mon.KernelVersion, "4.") { // 4.x
			mon.BpfModule = bcc.NewModule(bpfSource, []string{"-O2", "-DMONITOR_HOST_AND_CONTAINER"})
		} else { // 5.x
			mon.HostBpfModule = bcc.NewModule(bpfSource, []string{"-O2", "-DMONITOR_HOST"})
		}
	}

	if mon.BpfModule == nil {
		mon.BpfModule = bcc.NewModule(bpfSource, []string{"-O2"})
	}

	if mon.BpfModule == nil {
		return errors.New("bpf module is nil")
	}

	mon.LogFeeder.Print("Initialized the eBPF program")

	sysPrefix := bcc.GetSyscallPrefix()
	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "accept", "bind", "listen"}

	for _, syscallName := range systemCalls {
		kp, err := mon.BpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", syscallName))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
		}
		err = mon.BpfModule.AttachKprobe(sysPrefix+syscallName, kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kprobe %s: %v", syscallName, err)
		}
		kp, err = mon.BpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", syscallName))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
		}
		err = mon.BpfModule.AttachKretprobe(sysPrefix+syscallName, kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kretprobe %s: %v", syscallName, err)
		}
	}

	tracepoints := []string{"do_exit"}

	for _, tracepoint := range tracepoints {
		kp, err := mon.BpfModule.LoadKprobe(fmt.Sprintf("trace_%s", tracepoint))
		if err != nil {
			return fmt.Errorf("error loading kprobe %s: %v", tracepoint, err)
		}
		err = mon.BpfModule.AttachKprobe(tracepoint, kp, -1)
		if err != nil {
			return fmt.Errorf("error attaching kprobe %s: %v", tracepoint, err)
		}
	}

	eventsTable := bcc.NewTable(mon.BpfModule.TableId("sys_events"), mon.BpfModule)
	mon.SyscallChannel = make(chan []byte, 8192)
	mon.SyscallLostChannel = make(chan uint64)

	mon.SyscallPerfMap, err = bcc.InitPerfMapWithPageCnt(eventsTable, mon.SyscallChannel, mon.SyscallLostChannel, 64)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	if mon.EnableHostPolicy && !strings.HasPrefix(mon.KernelVersion, "4.") {
		for _, syscallName := range systemCalls {
			kp, err := mon.HostBpfModule.LoadKprobe(fmt.Sprintf("syscall__%s", syscallName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}
			err = mon.HostBpfModule.AttachKprobe(sysPrefix+syscallName, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", syscallName, err)
			}
			kp, err = mon.HostBpfModule.LoadKprobe(fmt.Sprintf("trace_ret_%s", syscallName))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", syscallName, err)
			}
			err = mon.HostBpfModule.AttachKretprobe(sysPrefix+syscallName, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kretprobe %s: %v", syscallName, err)
			}
		}

		tracepoints := []string{"do_exit"}

		for _, tracepoint := range tracepoints {
			kp, err := mon.HostBpfModule.LoadKprobe(fmt.Sprintf("trace_%s", tracepoint))
			if err != nil {
				return fmt.Errorf("error loading kprobe %s: %v", tracepoint, err)
			}
			err = mon.HostBpfModule.AttachKprobe(tracepoint, kp, -1)
			if err != nil {
				return fmt.Errorf("error attaching kprobe %s: %v", tracepoint, err)
			}
		}

		hostEventsTable := bcc.NewTable(mon.HostBpfModule.TableId("sys_events"), mon.HostBpfModule)
		mon.HostSyscallChannel = make(chan []byte, 8192)
		mon.HostSyscallLostChannel = make(chan uint64)

		mon.HostSyscallPerfMap, err = bcc.InitPerfMapWithPageCnt(hostEventsTable, mon.HostSyscallChannel, mon.HostSyscallLostChannel, 64)
		if err != nil {
			return fmt.Errorf("error initializing events perf map: %v", err)
		}
	}

	return nil
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.Stop()
	}

	if mon.EnableHostPolicy {
		if mon.HostSyscallPerfMap != nil {
			mon.HostSyscallPerfMap.Stop()
		}
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.EnableHostPolicy {
		if mon.HostBpfModule != nil {
			mon.HostBpfModule.Close()
		}
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	if mon.EnableHostPolicy {
		if mon.HostContextChan != nil {
			close(mon.HostContextChan)
		}
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
		mon.SyscallPerfMap.Start()
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

			if ctx.EventID == SYS_OPEN {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SYS_OPENAT {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SYS_EXECVE {
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

					// skip pushing the log if Audited is enabled

					if mon.EnableAuditd && ctx.Retval == PERMISSION_DENIED {
						continue
					}

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

					if mon.LogFeeder != nil {
						go mon.LogFeeder.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) == 4 { // enter
					// build a pid node

					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(containerID, pidNode)

					// generate a log with the base information

					log := mon.BuildLogBase(ContextCombined{ContainerID: containerID, ContextSys: ctx})

					// add arguments

					fd := ""
					procExecFlag := ""

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

					// skip pushing the log if Audited is enabled

					if mon.EnableAuditd && ctx.Retval == PERMISSION_DENIED {
						continue
					}

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

					if mon.LogFeeder != nil {
						go mon.LogFeeder.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == DO_EXIT {
				mon.DeleteActivePid(containerID, ctx)
				continue
			}

			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

		//nolint
		case _ = <-mon.SyscallLostChannel:
			continue
		}
	}
}

// TraceHostSyscall Function
func (mon *SystemMonitor) TraceHostSyscall() {
	if mon.HostSyscallPerfMap != nil {
		mon.HostSyscallPerfMap.Start()
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

			if ctx.EventID == SYS_OPEN {
				if len(args) != 2 {
					continue
				}
			} else if ctx.EventID == SYS_OPENAT {
				if len(args) != 3 {
					continue
				}
			} else if ctx.EventID == SYS_EXECVE {
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

					// skip pushing the log if Audited is enabled

					if mon.EnableAuditd && ctx.Retval == PERMISSION_DENIED {
						continue
					}

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

					if mon.LogFeeder != nil {
						go mon.LogFeeder.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) == 4 { // enter
					// build a pid node

					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActiveHostPid(ctx.HostPID, pidNode)

					// generate a log with the base information

					log := mon.BuildLogBase(ContextCombined{ContainerID: "", ContextSys: ctx})

					// add arguments

					fd := ""
					procExecFlag := ""

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

					// skip pushing the log if Audited is enabled

					if mon.EnableAuditd && ctx.Retval == PERMISSION_DENIED {
						continue
					}

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

					if mon.LogFeeder != nil {
						go mon.LogFeeder.PushLog(log)
					}
				}

				continue
			} else if ctx.EventID == DO_EXIT {
				mon.DeleteActiveHostPid(ctx.HostPID)
				continue
			}

			// push the context to the channel for logging
			mon.HostContextChan <- ContextCombined{ContainerID: "", ContextSys: ctx, ContextArgs: args}

		//nolint
		case _ = <-mon.SyscallLostChannel:
			continue
		}
	}
}
