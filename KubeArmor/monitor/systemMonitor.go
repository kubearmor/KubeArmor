package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iovisor/gobpf/bcc"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

var (
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/([0-9a-f]{64})`)
	kubePattern   = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
)

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
	SYSPOL_PROC     = 1
	SYSPOL_FILE     = 2
	SYSPOL_PROCFILE = 3
)

const (
	PERMISSION_DENIED = -13
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

	HostPID uint32
	PPID    uint32
	PID     uint32
	UID     uint32

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
	// logs
	LogFeeder *fd.Feeder

	// host name
	HostName string

	// host policy
	EnableHostPolicy bool

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.Mutex

	// container id -> (host) pid
	ActivePidMap     *map[string]tp.PidMap
	ActiveHostPidMap *map[string]tp.PidMap

	// pid map lock
	ActivePidMapLock **sync.Mutex

	// PidID + MntID -> container id
	NsMap map[NsKey]string

	// system monitor (for container)
	BpfModule *bcc.Module

	// context + args (for container)
	ContextChan chan ContextCombined

	// process + file (for container)
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *bcc.PerfMap

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

	// GKE
	IsCOS bool
}

// NewSystemMonitor Function
func NewSystemMonitor(feeder *fd.Feeder, enableHostPolicy bool, containers *map[string]tp.Container, containersLock **sync.Mutex, activePidMap *map[string]tp.PidMap, activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.Mutex) *SystemMonitor {
	mon := new(SystemMonitor)

	mon.LogFeeder = feeder

	mon.HostName = kl.GetHostName()
	mon.EnableHostPolicy = enableHostPolicy

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActivePidMap = activePidMap
	mon.ActiveHostPidMap = activeHostPidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.NsMap = make(map[NsKey]string)

	mon.ContextChan = make(chan ContextCombined, 4096)
	mon.HostContextChan = make(chan ContextCombined, 4096)

	mon.UntrackedNamespaces = []string{"kube-system"}

	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = bcc.GetHostByteOrder()

	mon.IsCOS = false

	return mon
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF(HomeDir string) error {
	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				mon.LogFeeder.Print("Detected Container-Optimized OS, started to download kernel headers for COS")

				// get kernel version
				kernelVersion := kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
				kernelVersion = strings.TrimSuffix(kernelVersion, "\n")

				// check and download kernel headers
				if err := exec.Command(HomeDir + "/GKE/download_cos_kernel_headers.sh").Run(); err != nil {
					mon.LogFeeder.Errf("Failed to download COS kernel headers (%s)", err.Error())
					return err
				}

				mon.LogFeeder.Printf("Downloaded kernel headers (%s)", kernelVersion)

				// set a new location for kernel headers
				os.Setenv("BCC_KERNEL_SOURCE", HomeDir+"/GKE/kernel/usr/src/linux-headers-"+kernelVersion)

				// just for safety
				time.Sleep(time.Second * 1)

				mon.IsCOS = true
			}
		}
	}

	content, err := ioutil.ReadFile(HomeDir + "/BPF/system_monitor.c")
	if err != nil {
		return err
	}
	bpfSource := string(content)

	mon.LogFeeder.Print("Initializing an eBPF program")

	mon.BpfModule = bcc.NewModule(bpfSource, []string{"-O2"})

	if mon.EnableHostPolicy {
		mon.HostBpfModule = bcc.NewModule(bpfSource, []string{"-O2", "-DMONITOR_HOST"})
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
	mon.SyscallChannel = make(chan []byte, 4096)
	mon.SyscallLostChannel = make(chan uint64)

	mon.SyscallPerfMap, err = bcc.InitPerfMapWithPageCnt(eventsTable, mon.SyscallChannel, mon.SyscallLostChannel, 64)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	if mon.EnableHostPolicy {
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
		mon.HostSyscallChannel = make(chan []byte, 4096)
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

	return nil
}

// ============================ //
// == PID-to-ContainerID Map == //
// ============================ //

// LookupContainerID Function
func (mon *SystemMonitor) LookupContainerID(pidns uint32, mntns uint32, pid uint32, newProcess bool) string {
	key := NsKey{PidNS: pidns, MntNS: mntns}
	if val, ok := mon.NsMap[key]; ok {
		return val
	}

	if newProcess { // if new process, look up container id
		containerID := ""

		// first shot: look up container id from cgroup

		cgroup, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return "" // this is nature, just meaning that the PID no longer exists
		}

		cgroupScanner := bufio.NewScanner(cgroup)
		for cgroupScanner.Scan() {
			line := cgroupScanner.Text()

			// k8s
			parts := kubePattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// docker
			parts = dockerPattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}
		}

		cgroup.Close()

		// update newly found container id
		if containerID != "" {
			mon.NsMap[key] = containerID
			return containerID
		}

		// alternative shot: look up container id from cmdline

		cmdline, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return "" // this is nature, just meaning that the PID no longer exists
		}

		cmdScanner := bufio.NewScanner(cmdline)
		for cmdScanner.Scan() {
			line := cmdScanner.Text()

			parts := strings.Split(line, "-id")
			if len(parts) < 2 {
				break
			}

			parts = strings.Split(parts[1], "-addr")
			if len(parts) < 2 {
				break
			}

			containerID = parts[0]
			break
		}

		cmdline.Close()

		// update newly found container id
		if containerID != "" {
			mon.NsMap[key] = containerID
			return containerID
		}
	}

	return ""
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *SystemMonitor) BuildPidNode(ctx SyscallContext, execPath string, args []string) tp.PidNode {
	node := tp.PidNode{}

	node.HostPID = ctx.HostPID
	node.PPID = ctx.PPID
	node.PID = ctx.PID
	node.UID = ctx.UID

	node.Comm = string(ctx.Comm[:])
	node.ExecPath = execPath

	for idx, arg := range args {
		if idx == 0 {
			continue
		} else {
			node.ExecPath = node.ExecPath + " " + arg
		}
	}

	node.Exited = false

	return node
}

// AddActivePid Function
func (mon *SystemMonitor) AddActivePid(containerID string, node tp.PidNode) {
	ActivePidMap := *(mon.ActivePidMap)
	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// add pid node to AcvtivePidMaps
	if pidMap, ok := ActivePidMap[containerID]; ok {
		pidMap[node.PID] = node
	} else {
		newPidMap := tp.PidMap{node.PID: node}
		ActivePidMap[containerID] = newPidMap
	}

	// add pid node to AcvtivePidMaps
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		pidMap[node.HostPID] = node
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		ActiveHostPidMap[containerID] = newPidMap
	}
}

// GetExecPath Function
func (mon *SystemMonitor) GetExecPath(containerID string, pid uint32) string {
	ActivePidMap := *(mon.ActivePidMap)

	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[pid]; ok {
			if node.PID == pid {
				return node.ExecPath
			}
		}
	}

	return ""
}

// GetExecPathWithHostPID Function
func (mon *SystemMonitor) GetExecPathWithHostPID(containerID string, hostPid uint32) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			if node.HostPID == hostPid {
				return node.ExecPath
			}
		}
	}

	return ""
}

// DeleteActivePid Function
func (mon *SystemMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	ActivePidMap := *(mon.ActivePidMap)
	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// delete execve(at) pid
	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[ctx.PID]; ok {
			if node.PID == ctx.PID {
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}

	// delete execve(at) host pid
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			if node.HostPID == ctx.HostPID {
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}
}

// CleanUpExitedHostPids Function
func (mon *SystemMonitor) CleanUpExitedHostPids() {
	now := time.Now()

	ActivePidMap := *(mon.ActivePidMap)
	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	for _, pidMap := range ActivePidMap {
		for pid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, pid)
				}
			}
		}
	}

	for _, pidMap := range ActiveHostPidMap {
		for pid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, pid)
				}
			}
		}
	}
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

			// get container id

			containerID := ""

			if ctx.PidID != 0 && ctx.MntID != 0 {
				if ctx.EventID == SYS_EXECVE || ctx.EventID == SYS_EXECVEAT {
					containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID, ctx.HostPID, true)
				} else {
					containerID = mon.LookupContainerID(ctx.PidID, ctx.MntID, ctx.HostPID, false)
				}

				if containerID != "" {
					ContainersLock.Lock()
					namespace := Containers[containerID].NamespaceName
					if kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
						ContainersLock.Unlock()
						continue
					}
					ContainersLock.Unlock()
				}
			}

			if containerID == "" {
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
				if len(args) == 2 {
					pidNode := mon.BuildPidNode(ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid(containerID, pidNode)
				} else if len(args) != 0 {
					continue
				}
			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) == 4 {
					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(containerID, pidNode)
				} else if len(args) != 0 {
					continue
				}
			} else if ctx.EventID == DO_EXIT {
				mon.DeleteActivePid(containerID, ctx)
				continue
			}

			// push the context to the channel for logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

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
				if len(args) == 2 {
					hostPID := strconv.FormatUint(uint64(ctx.HostPID), 10)
					pidNode := mon.BuildPidNode(ctx, args[0].(string), args[1].([]string))
					mon.AddActivePid(hostPID, pidNode)
				} else if len(args) != 0 {
					continue
				}
			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) == 4 {
					hostPID := strconv.FormatUint(uint64(ctx.HostPID), 10)
					pidNode := mon.BuildPidNode(ctx, args[1].(string), args[2].([]string))
					mon.AddActivePid(hostPID, pidNode)
				} else if len(args) != 0 {
					continue
				}
			} else if ctx.EventID == DO_EXIT {
				hostPID := strconv.FormatUint(uint64(ctx.HostPID), 10)
				mon.DeleteActivePid(hostPID, ctx)
				continue
			}

			// push the context to the channel for logging
			mon.HostContextChan <- ContextCombined{ContainerID: "", ContextSys: ctx, ContextArgs: args}

		case _ = <-mon.HostSyscallLostChannel:
			continue
		}
	}
}
