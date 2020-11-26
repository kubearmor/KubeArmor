package core

import (
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/events"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	adt "github.com/accuknox/KubeArmor/KubeArmor/audit"
	efc "github.com/accuknox/KubeArmor/KubeArmor/enforcer"
	mon "github.com/accuknox/KubeArmor/KubeArmor/monitor"
)

// ====================== //
// == KubeArmor Daemon == //
// ====================== //

// StopChan Channel
var StopChan chan struct{}

// WgDaemon Handler
var WgDaemon sync.WaitGroup

// HomeDir Directory
var HomeDir string

// FileContainerMonitor Path
var FileContainerMonitor string

// ActivePidMap to map container id and process id
var ActivePidMap map[string]tp.PidMap

// ActivePidMapLock for ActivePidMap
var ActivePidMapLock *sync.Mutex

// init Function
func init() {
	StopChan = make(chan struct{})
	WgDaemon = sync.WaitGroup{}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}

	// base directory
	HomeDir = dir

	// container monitor code location
	FileContainerMonitor = HomeDir + "/BPF/container_monitor.c"

	// shared map between container monitor and audit logger
	ActivePidMap = map[string]tp.PidMap{}
	ActivePidMapLock = &sync.Mutex{}
}

// KubeArmorDaemon Structure
type KubeArmorDaemon struct {
	// Docker event monitor
	EventChan <-chan events.Message

	// host name and IP
	HostName string
	HostIP   string

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.Mutex

	// container groups
	ContainerGroups     []tp.ContainerGroup
	ContainerGroupsLock *sync.Mutex

	// K8s pods
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.Mutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.Mutex

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// audit logger
	AuditLogger *adt.AuditLogger

	// logging option
	LogOption string

	// container monitor
	ContainerMonitor *mon.ContainerMonitor

	// configuration
	DefaultWaitTime int
	UptimeTimeStamp float64
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon() *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dm.EventChan = Docker.GetEventChannel()

	dm.HostName, _ = Docker.GetHostName()
	dm.HostIP = kl.GetExternalIPAddr()

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = &sync.Mutex{}

	dm.ContainerGroups = []tp.ContainerGroup{}
	dm.ContainerGroupsLock = &sync.Mutex{}

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = &sync.Mutex{}

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = &sync.Mutex{}

	dm.RuntimeEnforcer = nil

	dm.AuditLogger = nil
	dm.LogOption = "file:/KubeArmor/audit/kubearmor.log"

	dm.ContainerMonitor = nil

	dm.DefaultWaitTime = 1
	dm.UptimeTimeStamp = kl.GetUptimeTimestamp()

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	// close runtime enforcer
	dm.CloseRuntimeEnforcer()
	kg.PrintfNotInsert("Closed the runtime enforcer")

	// close audit logger
	dm.CloseAuditLogger()
	kg.PrintfNotInsert("Closed the audit logger")

	// close container monitor
	dm.CloseContainerMonitor()
	kg.PrintfNotInsert("Closed the container monitor")

	kg.PrintfNotInsert("Waiting for routine terminations")
	WgDaemon.Wait()

	kg.PrintfNotInsert("Terminated the KubeArmor")
}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGKILL,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// GetChan Function
func (dm *KubeArmorDaemon) GetChan() chan os.Signal {
	sigChan := GetOSSigChannel()

	select {
	case <-sigChan:
		kg.PrintfNotInsert("Got a signal to terminate the KubeArmor")
		close(StopChan)

		dm.DestroyKubeArmorDaemon()

		os.Exit(0)
	default:
		time.Sleep(time.Second * 1)
	}

	return sigChan
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer() bool {
	ret := true
	defer kg.HandleErrRet(&ret)

	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(HomeDir)

	kg.Print("Started to protect containers")

	return ret
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() {
	dm.RuntimeEnforcer.DestroyRuntimeEnforcer()
}

// ================== //
// == Audit Logger == //
// ================== //

// InitAuditLogger Function
func (dm *KubeArmorDaemon) InitAuditLogger() bool {
	ret := true
	defer kg.HandleErrRet(&ret)

	dm.AuditLogger = adt.NewAuditLogger(dm.LogOption, dm.HostName, dm.Containers, dm.ContainersLock, ActivePidMap, ActivePidMapLock)
	if err := dm.AuditLogger.InitAuditLogger(HomeDir); err != nil {
		return false
	}

	kg.Print("Started to monitor audit logs")

	return ret
}

// MonitorAuditLogs Function
func (dm *KubeArmorDaemon) MonitorAuditLogs() {
	defer kg.HandleErr()
	defer WgDaemon.Done()

	go dm.AuditLogger.MonitorAuditLogs()
}

// CloseAuditLogger Function
func (dm *KubeArmorDaemon) CloseAuditLogger() {
	dm.AuditLogger.DestroyAuditLogger()
}

// ======================= //
// == Container Monitor == //
// ======================= //

// InitContainerMonitor Function
func (dm *KubeArmorDaemon) InitContainerMonitor() bool {
	ret := true
	defer kg.HandleErrRet(&ret)

	dm.ContainerMonitor = mon.NewContainerMonitor(dm.HostName, dm.Containers, dm.ContainersLock, ActivePidMap, ActivePidMapLock, dm.UptimeTimeStamp)
	if err := dm.ContainerMonitor.InitBPF(HomeDir, FileContainerMonitor); err != nil {
		return false
	}

	kg.Print("Started to monitor system events")

	go dm.ContainerMonitor.TraceSyscall()
	go dm.ContainerMonitor.TraceSkb()

	go dm.ContainerMonitor.UpdateSystemLogs()

	return ret
}

// CloseContainerMonitor Function
func (dm *KubeArmorDaemon) CloseContainerMonitor() {
	dm.ContainerMonitor.RemoveBPF()
}

// ========== //
// == Main == //
// ========== //

// KubeArmor Function
func KubeArmor() {
	dm := NewKubeArmorDaemon()

	kg.Print("Started KubeArmor")

	// == //

	// initialize runtime enforcer
	if !dm.InitRuntimeEnforcer() {
		kg.Err("Failed to intialize the runtime enforcer")
		return
	}

	// initialize audit logger
	if !dm.InitAuditLogger() {
		kg.Err("Failed to intialize the audit logger")
		return
	}

	// initialize container monitor
	if !dm.InitContainerMonitor() {
		kg.Err("Failed to initialize the container monitor")
		return
	}

	// == //

	// monitor audit logs
	go dm.MonitorAuditLogs()
	WgDaemon.Add(1)

	// wait for a while (get pod data)
	time.Sleep(time.Second * 1)

	// monitor docker events
	go dm.MonitorDockerEvents()
	WgDaemon.Add(1)

	// == //

	if K8s.InitK8sClient() {
		// watch k8s pods
		go dm.WatchK8sPods()

		// watch security policies
		go dm.WatchSecurityPolicies()
	}

	// == //

	// listen for interrupt signals
	sigChan := dm.GetChan()
	<-sigChan
	kg.PrintfNotInsert("Got a signal to terminate the KubeArmor")
	close(StopChan)

	dm.DestroyKubeArmorDaemon()
}
