package core

import (
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

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

// ActivePidMap to map container id and process id
var ActivePidMap map[string]tp.PidMap

// ActivePidMapLock for ActivePidMap
var ActivePidMapLock *sync.Mutex

// init Function
func init() {
	StopChan = make(chan struct{})

	// shared map between container monitor and audit logger
	ActivePidMap = map[string]tp.PidMap{}
	ActivePidMapLock = &sync.Mutex{}
}

// KubeArmorDaemon Structure
type KubeArmorDaemon struct {
	// home directory
	HomeDir string

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

	// container monitor
	ContainerMonitor *mon.ContainerMonitor

	// logging
	AuditLogOption  string
	SystemLogOption string

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon(auditLogOption, systemLogOption string) *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	dm.HomeDir = dir

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
	dm.ContainerMonitor = nil

	dm.AuditLogOption = auditLogOption
	dm.SystemLogOption = systemLogOption

	dm.WgDaemon = sync.WaitGroup{}

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

	// wait for other routines
	kg.PrintfNotInsert("Waiting for routine terminations")
	dm.WgDaemon.Wait()

	kg.PrintfNotInsert("Terminated the KubeArmor")
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer() bool {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer()
	if dm.RuntimeEnforcer == nil {
		return false
	}

	return true
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
	dm.AuditLogger = adt.NewAuditLogger(dm.AuditLogOption, dm.Containers, dm.ContainersLock, ActivePidMap, ActivePidMapLock)
	if dm.AuditLogger == nil {
		return false
	}

	if err := dm.AuditLogger.InitAuditLogger(dm.HomeDir); err != nil {
		return false
	}

	return true
}

// MonitorAuditLogs Function
func (dm *KubeArmorDaemon) MonitorAuditLogs() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

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
	dm.ContainerMonitor = mon.NewContainerMonitor(dm.SystemLogOption, dm.Containers, dm.ContainersLock, ActivePidMap, ActivePidMapLock)
	if dm.ContainerMonitor == nil {
		return false
	}

	if err := dm.ContainerMonitor.InitBPF(dm.HomeDir); err != nil {
		return false
	}

	return true
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.ContainerMonitor.TraceSyscall()
	go dm.ContainerMonitor.UpdateSystemLogs()
}

// CloseContainerMonitor Function
func (dm *KubeArmorDaemon) CloseContainerMonitor() {
	dm.ContainerMonitor.DestroyContainerMonitor()
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

// ========== //
// == Main == //
// ========== //

// KubeArmor Function
func KubeArmor(auditLogOption, systemLogOption string) {
	// create a daemon
	dm := NewKubeArmorDaemon(auditLogOption, systemLogOption)

	kg.Print("Initializing KubeArmor")

	// initialize runtime enforcer
	if !dm.InitRuntimeEnforcer() {
		kg.Err("Failed to intialize the runtime enforcer")
		return
	}
	kg.Print("Started to protect containers")

	// initialize audit logger
	if !dm.InitAuditLogger() {
		kg.Err("Failed to intialize the audit logger")
		return
	}
	kg.Print("Started to monitor audit logs")

	// initialize container monitor
	if !dm.InitContainerMonitor() {
		kg.Err("Failed to initialize the container monitor")
		return
	}
	kg.Print("Started to monitor system events")

	// monitor audit logs (audit logger)
	go dm.MonitorAuditLogs()

	// monior system events (container monitor)
	go dm.MonitorSystemEvents()

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	if K8s.InitK8sClient() {
		// get current CRI
		cr := K8s.GetContainerRuntime()

		kg.Printf("Container Runtime: %s", cr)

		if strings.Contains(cr, "containerd") {
			// monitor containerd events
			go dm.MonitorContainerdEvents()
		} else if strings.Contains(cr, "docker") {
			// monitor docker events
			go dm.MonitorDockerEvents()
		}

		// watch k8s pods
		go dm.WatchK8sPods()

		// watch security policies
		go dm.WatchSecurityPolicies()
	}

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	kg.Print("Initialized KubeArmor")

	// == //

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	kg.PrintfNotInsert("Got a signal to terminate the KubeArmor")
	close(StopChan)

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
