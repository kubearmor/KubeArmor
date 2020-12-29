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
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

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
	// host name
	HostName string

	// logging type
	logType string

	// logging target
	logTarget string

	// logging feeder
	logFeeder *fd.Feeder

	// container id -> cotnainer
	Containers     map[string]tp.Container
	ContainersLock *sync.Mutex

	// container id -> host pid
	ActivePidMap     map[string]tp.PidMap
	ActivePidMapLock *sync.Mutex

	// security policies
	SecurityPolicyMap map[string][]tp.NetworkPolicy

	// container monitor
	BpfModule *bcc.Module

	// PidID + MntID -> container id
	NsMap map[NsKey]string

	// context + args
	ContextChan chan ContextCombined

	// host pid -> on/off
	ActivePidSkbMap     map[uint32]uint32
	ActivePidSkbMapLock *sync.Mutex

	// host pid -> network keys (src_ip + proto + src_port)
	BlockSkbMap map[uint32][]uint64

	// process + file
	SyscallChannel     chan []byte
	SyscallLostChannel chan uint64
	SyscallPerfMap     *bcc.PerfMap

	// skb (ip_output)
	SkbChannel     chan []byte
	SkbLostChannel chan uint64
	SkbPerfMap     *bcc.PerfMap

	// sys -> skb
	HostPidSkbMap *bcc.Table

	// syssec -> netsec
	NetworkMap *bcc.Table

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
func NewContainerMonitor(logOption string, containers map[string]tp.Container, containersLock *sync.Mutex, activePidMap map[string]tp.PidMap, activePidMapLock *sync.Mutex) *ContainerMonitor {
	mon := new(ContainerMonitor)

	mon.HostName = kl.GetHostName()

	if strings.Contains(logOption, "grpc:") {
		args := strings.Split(logOption, ":")

		mon.logType = args[0]
		mon.logTarget = args[1] + ":" + args[2] // ip:port
		mon.logFeeder = fd.NewFeeder(mon.logTarget, "SystemLog")

	} else if strings.Contains(logOption, "file:") {
		args := strings.Split(logOption, ":")

		mon.logType = args[0]
		mon.logTarget = args[1]

		// create log file
		kl.GetCommandWithoutOutput("/bin/touch", []string{mon.logTarget})

	} else if logOption == "stdout" {
		mon.logType = "stdout"
		mon.logTarget = ""

	} else {
		mon.logType = "none"
		mon.logTarget = ""
	}

	mon.Containers = containers
	mon.ContainersLock = containersLock

	mon.ActivePidMap = activePidMap
	mon.ActivePidMapLock = activePidMapLock

	mon.SecurityPolicyMap = map[string][]tp.NetworkPolicy{}

	mon.NsMap = make(map[NsKey]string)
	mon.ContextChan = make(chan ContextCombined, 1024)

	mon.ActivePidSkbMap = map[uint32]uint32{}
	mon.ActivePidSkbMapLock = &sync.Mutex{}

	mon.BlockSkbMap = map[uint32][]uint64{}

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
			kernelVersion := kl.GetCommandOutput("uname", []string{"-r"})
			kernelVersion = strings.TrimSuffix(kernelVersion, "\n")

			// check and download kernel headers
			kl.GetCommandWithoutOutput(HomeDir+"/GKE/download_cos_kernel_headers.sh", []string{})

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

	mon.BpfModule = bcc.NewModule(bpfSource, []string{"-w"})
	if mon.BpfModule == nil {
		return errors.New("bpf module is nil")
	}

	sysPrefix := bcc.GetSyscallPrefix()
	systemCalls := []string{
		"open", "close", // file
		"socket", "connect", "accept", "bind", "listen", // network
		"execve", "execveat"} // process

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

	tracepoints := []string{
		"do_exit"} // process

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

	// network [skb: ip_output]
	kp, err := mon.BpfModule.LoadKprobe("kprobe__ip_output")
	if err != nil {
		return fmt.Errorf("error loading kprobe %s: %v", "ip_output", err)
	}
	err = mon.BpfModule.AttachKprobe("ip_output", kp, -1)
	if err != nil {
		return fmt.Errorf("error attaching kprobe %s: %v", "ip_output", err)
	}

	eventsSkbTable := bcc.NewTable(mon.BpfModule.TableId("skb_events"), mon.BpfModule)
	mon.SkbChannel = make(chan []byte)
	mon.SkbLostChannel = make(chan uint64)

	mon.SkbPerfMap, err = bcc.InitPerfMap(eventsSkbTable, mon.SkbChannel, mon.SkbLostChannel)
	if err != nil {
		return fmt.Errorf("error initializing monitor_event perf map: %v", err)
	}

	mon.HostPidSkbMap = bcc.NewTable(mon.BpfModule.TableId("host_pid_skb_map"), mon.BpfModule)
	mon.NetworkMap = bcc.NewTable(mon.BpfModule.TableId("network_map"), mon.BpfModule)

	return nil
}

// DestroyContainerMonitor Function
func (mon *ContainerMonitor) DestroyContainerMonitor() {
	if mon.SyscallPerfMap != nil {
		mon.SyscallPerfMap.Stop()
	}

	if mon.SkbPerfMap != nil {
		mon.SkbPerfMap.Stop()
	}

	if mon.BpfModule != nil {
		mon.BpfModule.Close()
	}

	if mon.logFeeder != nil {
		mon.logFeeder.DestroyFeeder()
	}

	if mon.ContextChan != nil {
		close(mon.ContextChan)
	}
}

// ================= //
// == System Logs == //
// ================= //

// GetNameFromContainerID Function
func (mon *ContainerMonitor) GetNameFromContainerID(id string) (string, string, string) {
	mon.ContainersLock.Lock()
	defer mon.ContainersLock.Unlock()

	if val, ok := mon.Containers[id]; ok {
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
	log.TID = int32(msg.ContextSys.TID)
	log.UID = int32(msg.ContextSys.UID)

	log.Syscall = getSyscallName(int32(msg.ContextSys.EventID))
	log.Argnum = msg.ContextSys.Argnum
	log.Retval = msg.ContextSys.Retval

	if msg.ContextSys.Retval < 0 {
		message := getErrorMessage(msg.ContextSys.Retval)
		if message != "" {
			log.ErrorMessage = message
		}
	}

	log.Comm = string(msg.ContextSys.Comm[:bytes.IndexByte(msg.ContextSys.Comm[:], 0)])

	return log
}

// UpdateSystemLogs Function
func (mon *ContainerMonitor) UpdateSystemLogs() {
	defer kg.HandleErr()

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.ContextChan:
			if !valid {
				continue
			}

			if mon.logType == "none" {
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

				log.Data = "filename=" + fileName + " flags=" + fileOpenFlags

				if msg.ContextSys.Retval > 0 {
					log.Data = log.Data + " fd=" + strconv.FormatInt(msg.ContextSys.Retval, 10)
				}

			case SYS_CLOSE:
				if len(msg.ContextArgs) == 1 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						log.Data = "fd=" + strconv.Itoa(int(val))
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

				log.Data = "domain=" + sockDomain + " type=" + sockType + " protocol=" + sockProtocol

				if msg.ContextSys.Retval > 0 {
					log.Data = log.Data + " fd=" + strconv.FormatInt(msg.ContextSys.Retval, 10)
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

				log.Data = "fd=" + fd

				for k, v := range sockAddr {
					log.Data = log.Data + " " + k + "=" + v
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

				log.Data = "fd=" + fd

				for k, v := range sockAddr {
					log.Data = log.Data + " " + k + "=" + v
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

				log.Data = "fd=" + fd

				for k, v := range sockAddr {
					log.Data = log.Data + " " + k + "=" + v
				}

			case SYS_LISTEN:
				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						log.Data = "fd=" + strconv.Itoa(int(val))
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

				log.Data = "exec=" + procExecPath

				for idx, arg := range procArgs {
					if idx == 0 {
						continue
					} else {
						log.Data = log.Data + " a" + strconv.Itoa(idx) + "=" + arg
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

				log.Data = "fd=" + fd + " exec=" + procExecPath

				for idx, arg := range procArgs {
					if idx == 0 {
						continue
					} else {
						log.Data = log.Data + " a" + strconv.Itoa(idx) + "=" + arg
					}
				}

				log.Data = " flag=" + procExecFlag

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

				log.Data = "cap=" + cap + " syscall=" + syscall
			}

			// == //

			if log.Retval >= 0 {
				continue
			}

			// == //

			if mon.logType == "grpc" {
				mon.logFeeder.SendSystemLog(log)

			} else if mon.logType == "file" {
				arr, _ := json.Marshal(log)
				kl.StrToFile(string(arr), mon.logTarget)

			} else if mon.logType == "stdout" {
				arr, _ := json.Marshal(log)
				fmt.Println(string(arr))
			}
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
func (mon *ContainerMonitor) BuildPidNode(ctx SyscallContext, execPath string, policy tp.NetworkPolicy) tp.PidNode {
	node := tp.PidNode{}

	node.Policy = policy

	node.HostPID = ctx.HostPID
	node.PPID = ctx.PPID
	node.PID = ctx.PID
	node.TID = ctx.TID

	node.Comm = string(ctx.Comm[:])
	node.ExecPath = execPath

	if policy.PolicyType == SYSPOL_PROC {
		node.Monitored = true
	}

	node.Exited = false

	return node
}

// AddActivePid Function
func (mon *ContainerMonitor) AddActivePid(containerID string, node tp.PidNode) {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	// add pid node to AcvtivePidMaps
	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if _, ok := pidMap[node.HostPID]; !ok {
			pidMap[node.HostPID] = node
		}
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		mon.ActivePidMap[containerID] = newPidMap
	}
}

// UpdateActivePid Function
func (mon *ContainerMonitor) UpdateActivePid(containerID string, hostPid uint32, policy tp.NetworkPolicy) {
	if policy.PolicyType == 0 {
		return
	}

	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			if !node.Monitored {
				node.Policy = policy
				node.Monitored = true
				pidMap[hostPid] = node // update
			}
		}
	}
}

// DeleteActivePid Function
func (mon *ContainerMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	// delete execve(at) pid
	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			if node.HostPID == ctx.HostPID && node.PID == ctx.PID {
				if node.Monitored {
					mon.UpdateHostPidSkbMap(ctx.HostPID, false)
				}
				node.Exited = true
				node.ExitedTime = time.Now()
			}
		}
	}
}

// CleanUpExitedHostPids Function
func (mon *ContainerMonitor) CleanUpExitedHostPids() {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	now := time.Now()

	for _, pidMap := range mon.ActivePidMap {
		for hostPid, pidNode := range pidMap {
			if pidNode.Exited {
				if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
					delete(pidMap, hostPid)
				}
			}
		}
	}
}

// ============================ //
// == Network Policy Matches == //
// ============================ //

// IsSkippedExecPaths Function
func (mon *ContainerMonitor) IsSkippedExecPaths(path string) bool {
	return kl.ContainsElement(mon.UntrackedExecs, path)
}

// GetExecPathFromHostPID Function
func (mon *ContainerMonitor) GetExecPathFromHostPID(containerID string, hostPid uint32) string {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		if pidNode, ok := pidMap[hostPid]; ok {
			return pidNode.ExecPath
		}
	}

	return ""
}

// GetExecPathFromPPID Function
func (mon *ContainerMonitor) GetExecPathFromPPID(containerID string, ppid uint32) string {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		for _, pidNode := range pidMap {
			if pidNode.PID == ppid {
				return pidNode.ExecPath
			}
		}
	}

	return ""
}

// IsSkipFileDirectory Function
func (mon *ContainerMonitor) IsSkipFileDirectory(directory string) bool {
	for _, skipDir := range mon.UntrackedDirs {
		if strings.HasPrefix(directory, skipDir) {
			return true
		}
	}
	return false
}

// UpdateHostPidSkbMap Function
func (mon *ContainerMonitor) UpdateHostPidSkbMap(hostPid uint32, monitor bool) {
	var monitored uint32

	if monitor {
		monitored = 1
	} else {
		monitored = 0
	}

	mon.ActivePidSkbMapLock.Lock()
	defer mon.ActivePidSkbMapLock.Unlock()

	if monitor {
		if _, ok := mon.ActivePidSkbMap[hostPid]; !ok {
			if err := mon.HostPidSkbMap.SetP(unsafe.Pointer(&hostPid), unsafe.Pointer(&monitored)); err != nil {
				kg.Err(err.Error())
			}
			mon.ActivePidSkbMap[hostPid] = monitored
		}
	} else { // delete network keys
		if val, ok := mon.BlockSkbMap[hostPid]; ok {
			for _, networkKey := range val {
				if err := mon.NetworkMap.DeleteP(unsafe.Pointer(&networkKey)); err != nil {
					kg.Err(err.Error())
				}
			}
			delete(mon.BlockSkbMap, hostPid)
		}

		if _, ok := mon.ActivePidSkbMap[hostPid]; ok {
			if err := mon.HostPidSkbMap.DeleteP(unsafe.Pointer(&hostPid)); err != nil {
				kg.Err(err.Error())
			}
			delete(mon.ActivePidSkbMap, hostPid)
		}
	}
}

// UpdateHostPidSkbMapForChildren Function
func (mon *ContainerMonitor) UpdateHostPidSkbMapForChildren(containerID string, pid uint32, monitor bool) {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		for _, pidNode := range pidMap {
			if pidNode.PPID == pid {
				go mon.UpdateHostPidSkbMap(pidNode.HostPID, true)
				pidNode.Monitored = true
			}
		}
	}
}

// GetMatchedSecurityPolicy Function
func (mon *ContainerMonitor) GetMatchedSecurityPolicy(containerID string, eventID int32, hostPid, ppid, pid uint32, exec, file interface{}) tp.NetworkPolicy {
	matchedFirst := tp.NetworkPolicy{}

	securityPolicies := []tp.NetworkPolicy{}
	if val, ok := mon.SecurityPolicyMap[containerID]; ok {
		securityPolicies = val
	}

	execPath := ""
	fileName := ""

	if val, ok := exec.(string); ok {
		execPath = val
	}

	if val, ok := file.(string); ok {
		fileName = val
	}

	for _, policy := range securityPolicies {
		switch policy.PolicyType {
		case SYSPOL_PROCFILE:
			if eventID == SYS_EXECVE || eventID == SYS_EXECVEAT {
				if len(policy.Process.MatchPaths) > 0 { // exact match
					if kl.ContainsElement(policy.Process.MatchPaths, execPath) {
						matchedFirst = policy
					}
				} else {
					for _, name := range policy.Process.MatchNames {
						if strings.Contains(execPath, name) {
							matchedFirst = policy
						}
					}
				}
			} else if eventID == SYS_OPEN {
				pidPath := mon.GetExecPathFromHostPID(containerID, hostPid)
				ppidPath := mon.GetExecPathFromPPID(containerID, ppid)

				for _, execPath := range []string{ppidPath, pidPath} {
					if len(policy.File.MatchPaths) > 0 {
						if len(policy.Process.MatchPaths) > 0 { // file path + process path
							processMatched := false

							for _, path := range policy.Process.MatchPaths {
								if strings.Contains(path, execPath) {
									processMatched = true
								}
							}

							if processMatched && kl.ContainsElement(policy.File.MatchPaths, fileName) {
								go mon.UpdateHostPidSkbMap(hostPid, true)
								matchedFirst = policy
							}
						} else { // file path + process name
							processMatched := false
							for _, name := range policy.Process.MatchNames {
								if strings.Contains(execPath, name) {
									processMatched = true
								}
							}

							if processMatched && kl.ContainsElement(policy.File.MatchPaths, fileName) {
								go mon.UpdateHostPidSkbMap(hostPid, true)
								matchedFirst = policy
							}
						}
					} else {
						if len(policy.Process.MatchPaths) > 0 { // file name + process path
							fileMatch := false

							for _, name := range policy.File.MatchNames {
								if strings.Contains(fileName, name) {
									fileMatch = true
								}
							}

							if fileMatch && kl.ContainsElement(policy.Process.MatchPaths, execPath) {
								go mon.UpdateHostPidSkbMap(hostPid, true)
								matchedFirst = policy
							}
						} else { // file name + process name
							fileMatch := false

							for _, name := range policy.File.MatchNames {
								if strings.Contains(fileName, name) {
									fileMatch = true
								}
							}

							processMatched := false

							for _, name := range policy.Process.MatchNames {
								if strings.Contains(execPath, name) {
									processMatched = true
								}
							}

							if fileMatch && processMatched {
								// if a process already has child processes, they should be also monitored
								mon.UpdateHostPidSkbMapForChildren(containerID, pid, true)

								go mon.UpdateHostPidSkbMap(hostPid, true)
								matchedFirst = policy
							}
						}
					}
				}
			}

		case SYSPOL_PROC:
			if eventID == SYS_EXECVE || eventID == SYS_EXECVEAT {
				if len(policy.Process.MatchPaths) > 0 { // exact match
					if kl.ContainsElement(policy.Process.MatchPaths, execPath) {
						go mon.UpdateHostPidSkbMap(hostPid, true)
						return policy
					}
				} else {
					for _, name := range policy.Process.MatchNames {
						if strings.Contains(execPath, name) {
							go mon.UpdateHostPidSkbMap(hostPid, true)
							return policy
						}
					}
				}
			}

		case SYSPOL_FILE:
			if eventID == SYS_OPEN {
				if len(policy.File.MatchPaths) > 0 { // exact match
					if kl.ContainsElement(policy.File.MatchPaths, fileName) {
						go mon.UpdateHostPidSkbMap(hostPid, true)
						return policy
					}
				} else {
					for _, name := range policy.File.MatchNames {
						if strings.Contains(fileName, name) {
							go mon.UpdateHostPidSkbMap(hostPid, true)
							return policy
						}
					}
				}
			}
		}
	}

	// priority = proc > proc+file
	// priority = file > proc+file

	return matchedFirst
}

// GetMatchedSecurityPolicyFromPPID Function
func (mon *ContainerMonitor) GetMatchedSecurityPolicyFromPPID(containerID string, hostPid, ppid uint32) tp.NetworkPolicy {
	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	// check ppid whether if the parent process is monitored already
	if pidMap, ok := mon.ActivePidMap[containerID]; ok {
		for _, pidNode := range pidMap {
			if pidNode.PID == ppid {
				if pidNode.Policy.PolicyType == SYSPOL_PROCFILE {
					return pidNode.Policy
				} else if pidNode.Policy.PolicyType == SYSPOL_PROC {
					mon.UpdateHostPidSkbMap(hostPid, true)
					return pidNode.Policy
				}
			}
		}
	}

	return tp.NetworkPolicy{}
}

// ================================ //
// == Network Policy Enforcement == //
// ================================ //

// GetPolicyType Function
func GetPolicyType(policy tp.NetworkPolicy) int {
	procMatches := len(policy.Process.MatchPaths) + len(policy.Process.MatchNames)
	fileMatches := len(policy.File.MatchPaths) + len(policy.File.MatchNames)

	if fileMatches > 0 && procMatches > 0 {
		return SYSPOL_PROCFILE
	} else if procMatches > 0 {
		return SYSPOL_PROC
	} else {
		return SYSPOL_FILE
	}
}

// GetContainerIDs Function
func (mon *ContainerMonitor) GetContainerIDs(contNames []string) []string {
	mon.ContainersLock.Lock()
	defer mon.ContainersLock.Unlock()

	conIds := []string{}

	for _, conName := range contNames {
		for id, cont := range mon.Containers {
			if cont.ContainerName == conName {
				conIds = append(conIds, id)
				break
			}
		}
	}

	return conIds
}

// UpdateSecurityPolicies Function
func (mon *ContainerMonitor) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	// step 1: update SecurityPolicyMap

	updatedPolicies := []tp.NetworkPolicy{}

	for _, secPolicy := range conGroup.SecurityPolicies {
		for _, source := range secPolicy.Spec.Network.MatchSources {
			policy := tp.NetworkPolicy{}
			kl.Clone(source, &policy)

			policy.PolicyType = GetPolicyType(policy)
			policy.PolicyAction = secPolicy.Spec.Action

			updatedPolicies = append(updatedPolicies, policy)
		}
	}

	activeContainerIDs := mon.GetContainerIDs(conGroup.Containers)

	for _, containerID := range activeContainerIDs {
		mon.SecurityPolicyMap[containerID] = updatedPolicies
	}

	// step 2: update removed containers

	removedContainerIDs := []string{}

	for containerID := range mon.SecurityPolicyMap {
		if _, ok := mon.SecurityPolicyMap[containerID]; !ok {
			removedContainerIDs = append(removedContainerIDs, containerID)
		}
	}

	mon.ActivePidMapLock.Lock()
	defer mon.ActivePidMapLock.Unlock()

	// step 3: update ActivePidMaps and HostPidSkbMap

	for containerID, pidMaps := range mon.ActivePidMap {
		for hostPid, pidNode := range pidMaps {
			if pidNode.Monitored { // already monitored
				policies := []tp.NetworkPolicy{}
				if val, ok := mon.SecurityPolicyMap[containerID]; ok {
					policies = val
				}

				if !kl.ContainsElement(policies, pidNode.Policy) {
					pidNode.Policy = tp.NetworkPolicy{}
					pidNode.Monitored = false
					mon.UpdateHostPidSkbMap(hostPid, false)
					pidMaps[hostPid] = pidNode // update
				}
			} else { // if not
				policy := mon.GetMatchedSecurityPolicy(containerID, SYS_EXECVE, pidNode.HostPID, pidNode.PPID, pidNode.PID, pidNode.ExecPath, "")
				if policy.PolicyType != 0 {
					pidNode.Policy = policy
					if pidNode.Policy.PolicyType == SYSPOL_PROC {
						pidNode.Monitored = true
						mon.UpdateHostPidSkbMap(hostPid, true)
					}
					pidMaps[hostPid] = pidNode // update
				}
			}
		}
	}

	// step 4: clean up dead containers

	for _, containerID := range removedContainerIDs {
		if pidMap, ok := mon.ActivePidMap[containerID]; ok {
			for hostPid, pidNode := range pidMap {
				if pidNode.Monitored {
					mon.UpdateHostPidSkbMap(hostPid, false)
				}
			}
		}
		delete(mon.ActivePidMap, containerID)
	}
}

// ======================= //
// == System Call Trace == //
// ======================= //

// TraceSyscall Function
func (mon *ContainerMonitor) TraceSyscall() {
	defer kg.HandleErr()

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

			// skip namespaces
			mon.ContainersLock.Lock()
			namespace := mon.Containers[containerID].NamespaceName
			if mon.SkipNamespace && kl.ContainsElement(mon.UntrackedNamespaces, namespace) {
				mon.ContainersLock.Unlock()
				continue
			}
			mon.ContainersLock.Unlock()

			// check system policy
			if ctx.EventID == SYS_OPEN {
				if len(args) != 2 {
					continue
				}

				if mon.SkipDir && mon.IsSkipFileDirectory(args[0].(string)) {
					continue
				}

				policy := mon.GetMatchedSecurityPolicy(containerID, ctx.EventID, ctx.HostPID, ctx.PPID, ctx.PID, "", args[0])
				mon.UpdateActivePid(containerID, ctx.HostPID, policy)
			} else if ctx.EventID == SYS_EXECVE {
				if len(args) != 2 {
					continue
				}

				if mon.SkipExec && mon.IsSkippedExecPaths(args[0].(string)) {
					continue
				}

				policy := mon.GetMatchedSecurityPolicy(containerID, ctx.EventID, ctx.HostPID, ctx.PPID, ctx.PID, args[0], "")
				if policy.PolicyType == 0 { // if policy is nil, check ppid
					policy = mon.GetMatchedSecurityPolicyFromPPID(containerID, ctx.HostPID, ctx.PPID)
				}

				pidNode := mon.BuildPidNode(ctx, args[0].(string), policy)
				mon.AddActivePid(containerID, pidNode)
			} else if ctx.EventID == SYS_EXECVEAT {
				if len(args) != 4 {
					continue
				}

				if mon.SkipExec && mon.IsSkippedExecPaths(args[0].(string)) {
					continue
				}

				policy := mon.GetMatchedSecurityPolicy(containerID, ctx.EventID, ctx.HostPID, ctx.PPID, ctx.PID, args[1], "")
				if policy.PolicyType == 0 { // if policy is nil, check ppid
					policy = mon.GetMatchedSecurityPolicyFromPPID(containerID, ctx.HostPID, ctx.PPID)
				}

				pidNode := mon.BuildPidNode(ctx, args[1].(string), policy)
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

// =============== //
// == Skb Trace == //
// =============== //

// TraceSkb Function
func (mon *ContainerMonitor) TraceSkb() {
	defer kg.HandleErr()

	if mon.SkbPerfMap != nil {
		mon.SkbPerfMap.Start()
	} else {
		return
	}

	for {
		select {
		case <-StopChan:
			return

		case dataRaw, valid := <-mon.SkbChannel:
			if !valid {
				continue
			}

			var event SkbContext
			err := binary.Read(bytes.NewBuffer(dataRaw), mon.HostByteOrder, &event)
			if err != nil {
				kg.Printf("Failed to decode received data: %s\n", err)
				continue
			}

			containerID := mon.LookupContainerID(event.PidID, event.MntID, event.HostPID)
			if containerID == "" {
				continue
			}

			if event.NetworkKey == 0 {
				continue
			}

			if networkKeys, ok := mon.BlockSkbMap[event.HostPID]; ok {
				if !kl.ContainsElement(networkKeys, event.NetworkKey) {
					networkKeys = append(networkKeys, event.NetworkKey)
					mon.BlockSkbMap[event.HostPID] = networkKeys
				}
			} else {
				mon.BlockSkbMap[event.HostPID] = []uint64{event.NetworkKey}
			}

		case _ = <-mon.SkbLostChannel:
			continue
		}
	}
}
