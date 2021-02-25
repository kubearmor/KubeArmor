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
	SYS_OPEN  = 2
	SYS_CLOSE = 3

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

	// capabilities
	CAP_CAPABLE = 352
)

const (
	SYSPOL_PROC     = 1
	SYSPOL_FILE     = 2
	SYSPOL_PROCFILE = 3
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

// ContainerMonitor Structure
type ContainerMonitor struct {
	// logs
	LogFeeder *fd.Feeder

	// host name
	HostName string

	// namespace anme + container group name -> corresponding security policies
	SecurityPolicies     map[string]tp.MatchPolicies
	SecurityPoliciesLock *sync.Mutex

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.Mutex

	// container id -> pid
	ActivePidMap     map[string]tp.PidMap
	ActivePidMapLock *sync.Mutex

	// container id -> host pid
	ActiveHostPidMap     map[string]tp.PidMap
	ActiveHostPidMapLock *sync.Mutex

	// container monitor
	BpfModule *bcc.Module

	// PidID + MntID -> container id
	NsMap map[NsKey]string

	// context + args
	ContextChan chan ContextCombined

	// process + file
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *bcc.PerfMap

	// lists to skip
	UntrackedNamespaces []string

	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder

	// GKE
	IsCOS bool
}

// NewContainerMonitor Function
func NewContainerMonitor(feeder *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.Mutex) *ContainerMonitor {
	mon := new(ContainerMonitor)

	mon.LogFeeder = feeder

	mon.HostName = kl.GetHostName()

	mon.SecurityPolicies = map[string]tp.MatchPolicies{}
	mon.SecurityPoliciesLock = &sync.Mutex{}

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActivePidMap = map[string]tp.PidMap{}
	mon.ActivePidMapLock = &sync.Mutex{}

	mon.ActiveHostPidMap = map[string]tp.PidMap{}
	mon.ActiveHostPidMapLock = &sync.Mutex{}

	mon.NsMap = make(map[NsKey]string)
	mon.ContextChan = make(chan ContextCombined, 1024)

	mon.UntrackedNamespaces = []string{"kube-system"}

	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = bcc.GetHostByteOrder()

	mon.IsCOS = false

	return mon
}

// InitBPF Function
func (mon *ContainerMonitor) InitBPF(HomeDir string) error {
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

				// create directories
				if err := os.MkdirAll("/KubeArmor/audit", 0755); err != nil {
					mon.LogFeeder.Errf("Failed to create a target directory (/KubeArmor/audit, %s)", err.Error())
					return nil
				}

				for {
					// create symbolic link
					if err := exec.Command(HomeDir + "/GKE/create_symbolic_link.sh").Run(); err == nil {
						break
					} else {
						// wait until cos-auditd is ready
						time.Sleep(time.Second * 1)
					}
				}

				mon.IsCOS = true
			} else {
				// create directories
				if err := os.MkdirAll("/KubeArmor/audit", 0755); err != nil {
					mon.LogFeeder.Errf("Failed to create a target directory (/KubeArmor/audit, %s)", err.Error())
					return nil
				}

				// make a symbolic link
				if err := os.Symlink("/var/log/audit/audit.log", "/KubeArmor/audit/audit.log"); err != nil {
					mon.LogFeeder.Errf("Failed to make a symbolic link for audit.log (%s)", err.Error())
					return nil
				}
			}
		}
	}

	content, err := ioutil.ReadFile(HomeDir + "/BPF/container_monitor.c")
	if err != nil {
		return err
	}
	bpfSource := string(content)

	mon.LogFeeder.Print("Initializing an eBPF program")

	mon.BpfModule = bcc.NewModule(bpfSource, []string{})
	if mon.BpfModule == nil {
		return errors.New("bpf module is nil")
	}

	mon.LogFeeder.Print("Initialized the eBPF program")

	sysPrefix := bcc.GetSyscallPrefix()
	systemCalls := []string{"open", "close", "execve", "execveat", "socket", "connect", "accept", "bind", "listen"}

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

	tracepoints := []string{"do_exit"} // , "cap_capable"}

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
	mon.SyscallChannel = make(chan []byte, 1000)
	mon.SyscallLostChannel = make(chan uint64)

	mon.SyscallPerfMap, err = bcc.InitPerfMapWithPageCnt(eventsTable, mon.SyscallChannel, mon.SyscallLostChannel, 64)
	if err != nil {
		return fmt.Errorf("error initializing events perf map: %v", err)
	}

	return nil
}

// DestroyContainerMonitor Function
func (mon *ContainerMonitor) DestroyContainerMonitor() error {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.Stop()
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	return nil
}

// ========== //
// == Logs == //
// ========== //

// GetNameFromContainerID Function
func (mon *ContainerMonitor) GetNameFromContainerID(id string) (string, string, string) {
	Containers := *(mon.Containers)
	ContainersLock := *(mon.ContainersLock)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	if val, ok := Containers[id]; ok {
		return val.NamespaceName, val.ContainerGroupName, val.ContainerName
	}

	return "", "", ""
}

// BuildLogBase Function
func (mon *ContainerMonitor) BuildLogBase(msg ContextCombined) tp.Log {
	log := tp.Log{}

	log.UpdatedTime = kl.GetDateTimeNow()

	log.HostName = mon.HostName

	log.ContainerID = msg.ContainerID
	log.NamespaceName, log.PodName, log.ContainerName = mon.GetNameFromContainerID(log.ContainerID)

	log.HostPID = int32(msg.ContextSys.HostPID)
	log.PPID = int32(msg.ContextSys.PPID)
	log.PID = int32(msg.ContextSys.PID)
	log.UID = int32(msg.ContextSys.UID)

	if msg.ContextSys.EventID == SYS_EXECVE || msg.ContextSys.EventID == SYS_EXECVEAT {
		log.Source = mon.GetExecPath(msg.ContainerID, msg.ContextSys.PPID)
	} else {
		log.Source = mon.GetExecPath(msg.ContainerID, msg.ContextSys.PID)
	}

	if log.Source == "" {
		log.Source = string(msg.ContextSys.Comm[:bytes.IndexByte(msg.ContextSys.Comm[:], 0)])
	}

	return log
}

// UpdateLogs Function
func (mon *ContainerMonitor) UpdateLogs() {
	execLogMap := map[int32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.ContextChan:
			if !valid {
				continue
			}

			log := mon.BuildLogBase(msg)

			switch msg.ContextSys.EventID {
			case SYS_OPEN:
				var fileName string
				var fileOpenFlags string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						fileName = val
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						fileOpenFlags = val
					}
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "flags=" + fileOpenFlags

				if msg.ContextSys.Retval == -13 {
					continue
				}

			case SYS_CLOSE:
				var fd string

				if len(msg.ContextArgs) == 1 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "File"
				log.Resource = getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

			case SYS_EXECVE: // path, args
				var procExecPath string
				var procArgs []string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						procExecPath = val
					}
					if val, ok := msg.ContextArgs[1].([]string); ok {
						procArgs = val
					}

					log.Operation = "Process"
					log.Resource = procExecPath

					for idx, arg := range procArgs {
						if idx == 0 {
							continue
						} else {
							log.Resource = log.Resource + " " + arg
						}
					}

					log.Data = ""

					execLogMap[log.HostPID] = log

					continue
				} else {
					log = execLogMap[log.HostPID]
					delete(execLogMap, log.HostPID)

					if msg.ContextSys.Retval == -13 {
						continue
					}
				}

			case SYS_EXECVEAT: // dirfd, path, args, flags
				var fd string
				var procExecPath string
				var procArgs []string
				var procExecFlag string

				if len(msg.ContextArgs) == 4 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						procExecPath = val
					}
					if val, ok := msg.ContextArgs[2].([]string); ok {
						procArgs = val
					}
					if val, ok := msg.ContextArgs[3].(string); ok {
						procExecFlag = val
					}

					log.Operation = "Process"
					log.Resource = procExecPath

					for idx, arg := range procArgs {
						if idx == 0 {
							continue
						} else {
							log.Resource = log.Resource + " " + arg
						}
					}

					log.Data = "fd=" + fd + " flag=" + procExecFlag

					execLogMap[log.HostPID] = log

					continue
				} else {
					log = execLogMap[log.HostPID]
					delete(execLogMap, log.HostPID)

					if msg.ContextSys.Retval == -13 {
						continue
					}
				}

			case SYS_SOCKET: // domain, type, proto
				var sockDomain string
				var sockType string
				var sockProtocol string

				if len(msg.ContextArgs) == 3 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						sockDomain = val
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						sockType = val
					}
					if val, ok := msg.ContextArgs[2].(int32); ok {
						sockProtocol = strconv.Itoa(int(val))
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " domain=" + sockDomain + " type=" + sockType + " protocol=" + sockProtocol
				log.Data = ""

			case SYS_CONNECT: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

				log.Data = "fd=" + fd

			case SYS_ACCEPT: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

			case SYS_BIND: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

				log.Data = "fd=" + fd

			case SYS_LISTEN: // fd
				var fd string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

			case CAP_CAPABLE:
				var cap string
				var syscall string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						cap = val
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						syscall = val
					}

				}

				log.Operation = "Capabilities"
				log.Resource = "capability=" + cap + " syscall=" + syscall
				log.Data = ""

			default:
				continue
			}

			// == //

			if msg.ContextSys.Retval < 0 {
				message := getErrorMessage(msg.ContextSys.Retval)
				if message != "" {
					log.Result = fmt.Sprintf("%s", message)
				} else {
					log.Result = fmt.Sprintf("Unknown (%d)", msg.ContextSys.Retval)
				}
			} else {
				log.Result = "Passed"
			}

			// == //

			log = mon.UpdateMatchedPolicy(log, msg.ContextSys.Retval)
			if log.Type == "" {
				continue
			}

			if mon.LogFeeder != nil {
				mon.LogFeeder.PushLog(log)
			}

			// == //
		}
	}
}

// ============================ //
// == PID-to-ContainerID Map == //
// ============================ //

// LookupContainerID Function
func (mon *ContainerMonitor) LookupContainerID(pidns uint32, mntns uint32, pid uint32) string {
	// approach 1: look up container id from map

	key := NsKey{PidNS: pidns, MntNS: mntns}
	if val, ok := mon.NsMap[key]; ok {
		return val
	}

	containerID := ""

	// approach 2: look up container id from cgroup

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

	// approach 3: look up container id from cmdline

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

	return ""
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *ContainerMonitor) BuildPidNode(ctx SyscallContext, execPath string, args []string) tp.PidNode {
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
func (mon *ContainerMonitor) AddActivePid(containerID string, node tp.PidNode) {
	mon.ActivePidMapLock.Lock()

	// add pid node to AcvtivePidMaps
	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if _, ok := pidMap[node.PID]; !ok {
			pidMap[node.PID] = node
		}
	} else {
		newPidMap := tp.PidMap{node.PID: node}
		mon.ActivePidMap[containerID] = newPidMap
	}

	mon.ActivePidMapLock.Unlock()

	mon.ActiveHostPidMapLock.Lock()

	// add pid node to AcvtivePidMaps
	if pidMap, ok := mon.ActiveHostPidMap[containerID]; ok {
		if _, ok := pidMap[node.HostPID]; !ok {
			pidMap[node.HostPID] = node
		}
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		mon.ActiveHostPidMap[containerID] = newPidMap
	}

	mon.ActiveHostPidMapLock.Unlock()
}

// GetExecPath Function
func (mon *ContainerMonitor) GetExecPath(containerID string, pid uint32) string {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if node, ok := pidMap[pid]; ok {
			if node.PID == pid {
				return node.ExecPath
			}
		}
	}

	return ""
}

// GetExecPathWithHostPID Function
func (mon *ContainerMonitor) GetExecPathWithHostPID(containerID string, hostPid uint32) string {
	mon.ActiveHostPidMapLock.Lock()
	defer mon.ActiveHostPidMapLock.Unlock()

	if pidMap, ok := mon.ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			if node.HostPID == hostPid {
				return node.ExecPath
			}
		}
	}

	return ""
}

// DeleteActivePid Function
func (mon *ContainerMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	mon.ActivePidMapLock.Lock()

	// delete execve(at) pid
	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if node, ok := pidMap[ctx.PID]; ok {
			if node.PID == ctx.PID {
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}

	mon.ActivePidMapLock.Unlock()

	mon.ActiveHostPidMapLock.Lock()

	// delete execve(at) host pid
	if pidMap, ok := mon.ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			if node.HostPID == ctx.HostPID {
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}

	mon.ActiveHostPidMapLock.Unlock()
}

// CleanUpExitedHostPids Function
func (mon *ContainerMonitor) CleanUpExitedHostPids() {
	now := time.Now()

	mon.ActivePidMapLock.Lock()

	for _, pidMap := range mon.ActivePidMap {
		for pid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, pid)
				}
			}
		}
	}

	mon.ActivePidMapLock.Unlock()

	mon.ActiveHostPidMapLock.Lock()

	for _, pidMap := range mon.ActiveHostPidMap {
		for pid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, pid)
				}
			}
		}
	}

	mon.ActiveHostPidMapLock.Unlock()
}

// ======================= //
// == System Call Trace == //
// ======================= //

// TraceSyscall Function
func (mon *ContainerMonitor) TraceSyscall() {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.Start()
	} else {
		return
	}

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
				mon.LogFeeder.Err(err.Error())
				continue
			}

			args, err := GetArgs(dataBuff, ctx.Argnum)
			if err != nil {
				continue
			}

			// skip if container id not found
			containerID := mon.LookupContainerID(ctx.PidID, ctx.MntID, ctx.HostPID)
			if containerID == "" {
				continue
			}

			Containers := *(mon.Containers)
			ContainersLock := *(mon.ContainersLock)

			// skip namespaces
			ContainersLock.Lock()
			namespace := Containers[containerID].NamespaceName
			if kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
				ContainersLock.Unlock()
				continue
			}
			ContainersLock.Unlock()

			if ctx.EventID == SYS_OPEN {
				if len(args) != 2 {
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

			// push the context to the channel for system logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

		case _ = <-mon.SyscallLostChannel:
			continue
		}
	}
}
