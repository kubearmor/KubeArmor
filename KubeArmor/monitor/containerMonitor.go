package monitor

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iovisor/gobpf/bcc"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

var (
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/([0-9a-f]{64})`)
	kubePattern1  = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
	kubePattern2  = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
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
	// audit logs
	auditLogType   string
	auditLogTarget string
	auditLogFeeder *fd.Feeder

	// system logs
	systemLogType   string
	systemLogTarget string
	systemLogFeeder *fd.Feeder

	// host name
	HostName string

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.Mutex

	// container id -> host pid
	ActivePidMap     *map[string]tp.PidMap
	ActivePidMapLock **sync.Mutex

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

	// flags to skip
	SkipNamespace bool
	SkipExec      bool
	SkipDir       bool

	// lists to skip
	UntrackedNamespaces []string
	UntrackedExecs      []string
	UntrackedDirs       []string

	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder
}

// NewContainerMonitor Function
func NewContainerMonitor(auditLogOption string, systemLogOption string, containers *map[string]tp.Container, containersLock **sync.Mutex, activePidMap *map[string]tp.PidMap, activePidMapLock **sync.Mutex) *ContainerMonitor {
	mon := new(ContainerMonitor)

	mon.HostName = kl.GetHostName()

	// audit logs

	if strings.Contains(auditLogOption, "grpc:") {
		args := strings.Split(auditLogOption, ":")

		mon.auditLogType = args[0]
		mon.auditLogTarget = args[1] + ":" + args[2] // ip:port
		mon.auditLogFeeder = fd.NewFeeder(mon.auditLogTarget, "AuditLog")

	} else if strings.Contains(auditLogOption, "file:") {
		args := strings.Split(auditLogOption, ":")

		mon.auditLogType = args[0]
		mon.auditLogTarget = args[1]

		// get the directory part from the path
		dirLog := filepath.Dir(mon.auditLogTarget)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			kg.Errf("Failed to create a target directory (%s)", err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(mon.auditLogTarget)
		if err != nil {
			kg.Errf("Failed to create a target file (%s)", err.Error())
			return nil
		}
		targetFile.Close()

	} else if auditLogOption == "stdout" {
		mon.auditLogType = "stdout"
		mon.auditLogTarget = ""

	} else {
		mon.auditLogType = "none"
		mon.auditLogTarget = ""
	}

	// system logs

	if strings.Contains(systemLogOption, "grpc:") {
		args := strings.Split(systemLogOption, ":")

		mon.systemLogType = args[0]
		mon.systemLogTarget = args[1] + ":" + args[2] // ip:port
		mon.systemLogFeeder = fd.NewFeeder(mon.systemLogTarget, "SystemLog")

	} else if strings.Contains(systemLogOption, "file:") {
		args := strings.Split(systemLogOption, ":")

		mon.systemLogType = args[0]
		mon.systemLogTarget = args[1]

		// get the directory part from the path
		dirLog := filepath.Dir(mon.systemLogTarget)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			kg.Errf("Failed to create a target directory (%s)", err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(mon.systemLogTarget)
		if err != nil {
			kg.Errf("Failed to create a target file (%s)", err.Error())
			return nil
		}
		targetFile.Close()

	} else if systemLogOption == "stdout" {
		mon.systemLogType = "stdout"
		mon.systemLogTarget = ""

	} else {
		mon.systemLogType = "none"
		mon.systemLogTarget = ""
	}

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActivePidMap = activePidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.NsMap = make(map[NsKey]string)
	mon.ContextChan = make(chan ContextCombined, 1024)

	mon.SkipNamespace = true
	mon.SkipExec = true
	mon.SkipDir = true

	mon.UntrackedNamespaces = []string{"kube-system"}
	mon.UntrackedExecs = []string{}
	mon.UntrackedDirs = []string{}

	mon.UptimeTimeStamp = kl.GetUptimeTimestamp()
	mon.HostByteOrder = bcc.GetHostByteOrder()

	return mon
}

// InitBPF Function
func (mon *ContainerMonitor) InitBPF(HomeDir string) error {
	// check if COS
	if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
		s := string(b)
		if strings.Contains(s, "Container-Optimized OS") {
			kg.Print("Detected Container-Optimized OS, started to download kernel headers for COS")

			// get kernel version
			kernelVersion := kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
			kernelVersion = strings.TrimSuffix(kernelVersion, "\n")

			// check and download kernel headers
			if err := exec.Command(HomeDir + "/GKE/download_cos_kernel_headers.sh").Run(); err != nil {
				kg.Errf("Failed to download COS kernel headers (%s)", err.Error())
				return err
			}

			kg.Printf("Downloaded kernel headers (%s)", kernelVersion)

			// set a new location for kernel headers
			os.Setenv("BCC_KERNEL_SOURCE", HomeDir+"/GKE/kernel/usr/src/linux-headers-"+kernelVersion)

			// just for safety
			time.Sleep(time.Second * 1)
		}
	}

	content, err := ioutil.ReadFile(HomeDir + "/BPF/container_monitor.c")
	if err != nil {
		return err
	}
	bpfSource := string(content)

	kg.Print("Initializing an eBPF program")

	mon.BpfModule = bcc.NewModule(bpfSource, []string{"-w"})
	if mon.BpfModule == nil {
		return errors.New("bpf module is nil")
	}

	kg.Print("Initialized the eBPF program")

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

	if mon.auditLogFeeder != nil {
		mon.auditLogFeeder.DestroyFeeder()
	}

	if mon.systemLogFeeder != nil {
		mon.systemLogFeeder.DestroyFeeder()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}

	return nil
}

// ================= //
// == System Logs == //
// ================= //

// GetNameFromContainerID Function
func (mon *ContainerMonitor) GetNameFromContainerID(id string) (string, string, string) {
	ContainersLock := *(mon.ContainersLock)
	Containers := *(mon.Containers)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	if val, ok := Containers[id]; ok {
		return val.NamespaceName, val.ContainerGroupName, val.ContainerName
	}

	return "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET"
}

// BuildSystemLogCommon Function
func (mon *ContainerMonitor) BuildSystemLogCommon(msg ContextCombined) tp.SystemLog {
	log := tp.SystemLog{}

	log.UpdatedTime = kl.GetDateTimeFromTimestamp(mon.UptimeTimeStamp + (float64(msg.ContextSys.Ts) / 1000000000.0))

	log.HostName = mon.HostName

	log.ContainerID = msg.ContainerID
	log.NamespaceName, log.PodName, log.ContainerName = mon.GetNameFromContainerID(msg.ContainerID)

	log.HostPID = int32(msg.ContextSys.HostPID)
	log.PPID = int32(msg.ContextSys.PPID)
	log.PID = int32(msg.ContextSys.PID)
	log.UID = int32(msg.ContextSys.UID)

	log.Operation = "syscall"
	log.Resource = getSyscallName(int32(msg.ContextSys.EventID))

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

	log.Source = string(msg.ContextSys.Comm[:bytes.IndexByte(msg.ContextSys.Comm[:], 0)])

	return log
}

// UpdateSystemLogs Function
func (mon *ContainerMonitor) UpdateSystemLogs() {
	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.ContextChan:
			if !valid {
				continue
			}

			if mon.systemLogType == "none" && msg.ContextSys.Retval != -1 {
				continue
			}

			log := mon.BuildSystemLogCommon(msg)

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

				log.Args = "filename=" + fileName + " flags=" + fileOpenFlags

				if msg.ContextSys.Retval > 0 {
					log.Args = log.Args + " fd=" + strconv.FormatInt(msg.ContextSys.Retval, 10)
				}

			case SYS_CLOSE:
				if len(msg.ContextArgs) == 1 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						log.Args = "fd=" + strconv.Itoa(int(val))
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

				log.Args = "domain=" + sockDomain + " type=" + sockType + " protocol=" + sockProtocol

				if msg.ContextSys.Retval > 0 {
					log.Args = log.Args + " fd=" + strconv.FormatInt(msg.ContextSys.Retval, 10)
				}

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

				log.Args = "fd=" + fd

				for k, v := range sockAddr {
					log.Args = log.Args + " " + k + "=" + v
				}

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

				log.Args = "fd=" + fd

				for k, v := range sockAddr {
					log.Args = log.Args + " " + k + "=" + v
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

				log.Args = "fd=" + fd

				for k, v := range sockAddr {
					log.Args = log.Args + " " + k + "=" + v
				}

			case SYS_LISTEN:
				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						log.Args = "fd=" + strconv.Itoa(int(val))
					}
				}

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
				}

				log.Args = "exec=" + procExecPath

				for idx, arg := range procArgs {
					if idx == 0 {
						continue
					} else {
						log.Args = log.Args + " a" + strconv.Itoa(idx) + "=" + arg
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
				}

				log.Args = "fd=" + fd + " exec=" + procExecPath

				for idx, arg := range procArgs {
					if idx == 0 {
						continue
					} else {
						log.Args = log.Args + " a" + strconv.Itoa(idx) + "=" + arg
					}
				}

				log.Args = " flag=" + procExecFlag

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

				log.Args = "cap=" + cap + " syscall=" + syscall
			}

			// == //

			if mon.systemLogType == "grpc" {
				mon.systemLogFeeder.SendSystemLog(log)

			} else if mon.systemLogType == "file" {
				arr, _ := json.Marshal(log)
				kl.StrToFile(string(arr), mon.systemLogTarget)

			} else if mon.systemLogType == "stdout" {
				arr, _ := json.Marshal(log)
				fmt.Println(string(arr))
			}

			if msg.ContextSys.Retval == -1 {
				auditLog := tp.AuditLog{}

				auditLog.UpdatedTime = log.UpdatedTime

				auditLog.HostName = log.HostName

				auditLog.ContainerID = log.ContainerID
				auditLog.ContainerName = log.ContainerName

				auditLog.NamespaceName = log.NamespaceName
				auditLog.PodName = log.PodName

				auditLog.HostPID = log.HostPID

				auditLog.Source = log.Source
				auditLog.Operation = log.Operation
				auditLog.Resource = log.Resource
				auditLog.Result = fmt.Sprintf("Failed (%s)", log.Result)

				auditLog.RawData = ""

				if mon.auditLogType == "grpc" {
					mon.auditLogFeeder.SendAuditLog(auditLog)

				} else if mon.auditLogType == "file" {
					arr, _ := json.Marshal(log)
					kl.StrToFile(string(arr), mon.auditLogTarget)

				} else if mon.auditLogType == "stdout" {
					arr, _ := json.Marshal(log)
					fmt.Println(string(arr))
				}
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

	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "" // this is nature, just meaning that the PID no longer exists
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if kl.IsK8sEnv() { // kubernetes
		for scanner.Scan() {
			line := scanner.Text()

			// k8s
			parts := kubePattern1.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// k8s
			parts = kubePattern2.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}
		}
	} else { // docker
		for scanner.Scan() {
			line := scanner.Text()
			parts := dockerPattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}
		}
	}

	// update newly found container id
	if containerID != "" {
		mon.NsMap[key] = containerID
	}

	return ""
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *ContainerMonitor) BuildPidNode(ctx SyscallContext, execPath string) tp.PidNode {
	node := tp.PidNode{}

	node.HostPID = ctx.HostPID
	node.PPID = ctx.PPID
	node.PID = ctx.PID

	node.Comm = string(ctx.Comm[:])
	node.ExecPath = execPath

	node.Exited = false

	return node
}

// AddActivePid Function
func (mon *ContainerMonitor) AddActivePid(containerID string, node tp.PidNode) {
	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMap := *(mon.ActivePidMap)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// add pid node to AcvtivePidMaps
	if pidMap, ok := ActivePidMap[containerID]; ok {
		if _, ok := pidMap[node.HostPID]; !ok {
			pidMap[node.HostPID] = node
		}
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		ActivePidMap[containerID] = newPidMap
	}
}

// DeleteActivePid Function
func (mon *ContainerMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMap := *(mon.ActivePidMap)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// delete execve(at) pid
	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			if node.HostPID == ctx.HostPID && node.PID == ctx.PID {
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}
}

// CleanUpExitedHostPids Function
func (mon *ContainerMonitor) CleanUpExitedHostPids() {
	ActivePidMapLock := *(mon.ActivePidMapLock)
	ActivePidMap := *(mon.ActivePidMap)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	now := time.Now()

	for _, pidMap := range ActivePidMap {
		for hostPid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, hostPid)
				}
			}
		}
	}
}

// ======================= //
// == System Call Trace == //
// ======================= //

// IsSkipFileDirectory Function
func (mon *ContainerMonitor) IsSkipFileDirectory(directory string) bool {
	for _, skipDir := range mon.UntrackedDirs {
		if strings.HasPrefix(directory, skipDir) {
			return true
		}
	}
	return false
}

// IsSkippedExecPaths Function
func (mon *ContainerMonitor) IsSkippedExecPaths(path string) bool {
	return kl.ContainsElement(mon.UntrackedExecs, path)
}

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
				kg.Err(err.Error())
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

			ContainersLock := *(mon.ContainersLock)
			Containers := *(mon.Containers)

			// skip namespaces
			ContainersLock.Lock()
			namespace := Containers[containerID].NamespaceName
			if mon.SkipNamespace && kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
				ContainersLock.Unlock()
				continue
			}
			ContainersLock.Unlock()

			if ctx.EventID == SYS_OPEN {
				if len(args) != 2 {
					continue
				}

				if mon.SkipDir && mon.IsSkipFileDirectory(args[0].(string)) {
					continue
				}

			} else if ctx.EventID == SYS_EXECVE {
				if len(args) != 2 {
					continue
				}

				if mon.SkipExec && mon.IsSkippedExecPaths(args[0].(string)) {
					continue
				}

				pidNode := mon.BuildPidNode(ctx, args[0].(string))
				mon.AddActivePid(containerID, pidNode)

			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) != 4 {
					continue
				}

				if mon.SkipExec && mon.IsSkippedExecPaths(args[0].(string)) {
					continue
				}

				pidNode := mon.BuildPidNode(ctx, args[1].(string))
				mon.AddActivePid(containerID, pidNode)

			} else if ctx.EventID == DO_EXIT {
				mon.DeleteActivePid(containerID, ctx)
			}

			// push the context to the channel for system logging
			mon.ContextChan <- ContextCombined{ContainerID: containerID, ContextSys: ctx, ContextArgs: args}

		case _ = <-mon.SyscallLostChannel:
			continue
		}
	}
}
