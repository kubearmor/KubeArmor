package core

import (
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	adt "github.com/accuknox/KubeArmor/KubeArmor/audit"
	efc "github.com/accuknox/KubeArmor/KubeArmor/enforcer"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	mon "github.com/accuknox/KubeArmor/KubeArmor/monitor"
)

// ====================== //
// == KubeArmor Daemon == //
// ====================== //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// KubeArmorDaemon Structure
type KubeArmorDaemon struct {
	// options
	EnableAuditd     bool
	EnableHostPolicy bool
	EnableSystemLog  bool

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	// container groups
	ContainerGroups     []tp.ContainerGroup
	ContainerGroupsLock *sync.RWMutex

	// K8s pods
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// Host Security policies
	HostSecurityPolicies     []tp.HostSecurityPolicy
	HostSecurityPoliciesLock *sync.RWMutex

	// container id -> (host) pid
	ActivePidMap     map[string]tp.PidMap
	ActiveHostPidMap map[string]tp.PidMap
	ActivePidMapLock *sync.RWMutex

	// host pid
	ActiveHostMap     map[uint32]tp.PidMap
	ActiveHostMapLock *sync.RWMutex

	// log feeder
	LogFeeder *fd.Feeder

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// system monitor
	SystemMonitor *mon.SystemMonitor

	// audit logger
	AuditLogger *adt.AuditLogger

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon(enableAuditd, enableHostPolicy, enableSystemLog bool) *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dm.EnableAuditd = enableAuditd
	dm.EnableHostPolicy = enableHostPolicy
	dm.EnableSystemLog = enableSystemLog

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

	dm.ContainerGroups = []tp.ContainerGroup{}
	dm.ContainerGroupsLock = new(sync.RWMutex)

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)

	dm.HostSecurityPolicies = []tp.HostSecurityPolicy{}
	dm.HostSecurityPoliciesLock = new(sync.RWMutex)

	dm.ActivePidMap = map[string]tp.PidMap{}
	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.ActiveHostMap = map[uint32]tp.PidMap{}
	dm.ActiveHostMapLock = new(sync.RWMutex)

	dm.LogFeeder = nil
	dm.SystemMonitor = nil
	dm.RuntimeEnforcer = nil
	dm.AuditLogger = nil

	dm.WgDaemon = sync.WaitGroup{}

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	if dm.RuntimeEnforcer != nil {
		// close runtime enforcer
		dm.CloseRuntimeEnforcer()
		dm.LogFeeder.Print("Stopped the runtime enforcer")
	}

	if dm.SystemMonitor != nil {
		// close system monitor
		dm.CloseSystemMonitor()
		dm.LogFeeder.Print("Stopped the system monitor")
	}

	if dm.EnableAuditd {
		if dm.AuditLogger != nil {
			// close audit logger
			dm.CloseAuditLogger()
			dm.LogFeeder.Print("Stopped the audit logger")
		}
	}

	dm.LogFeeder.Print("Terminated the KubeArmor")

	// wait for a while
	time.Sleep(time.Second * 1)

	// close log feeder
	dm.CloseLogFeeder()
	kg.Print("Stopped the log feeder")

	// wait for other routines
	kg.Print("Waiting for remaining routine terminations")
	dm.WgDaemon.Wait()
}

// ================ //
// == Log Feeder == //
// ================ //

// InitLogFeeder Function
func (dm *KubeArmorDaemon) InitLogFeeder(gRPCPort, logPath string) bool {
	dm.LogFeeder = fd.NewFeeder(gRPCPort, logPath, dm.EnableSystemLog)
	if dm.LogFeeder == nil {
		return false
	}

	return true
}

// ServeLogFeeds Function
func (dm *KubeArmorDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.LogFeeder.ServeLogFeeds()
}

// CloseLogFeeder Function
func (dm *KubeArmorDaemon) CloseLogFeeder() {
	dm.LogFeeder.DestroyFeeder()
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer() bool {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(dm.LogFeeder, dm.EnableAuditd, dm.EnableHostPolicy)
	if dm.RuntimeEnforcer == nil {
		return false
	}

	return true
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() {
	dm.RuntimeEnforcer.DestroyRuntimeEnforcer()
}

// ==================== //
// == System Monitor == //
// ==================== //

// InitSystemMonitor Function
func (dm *KubeArmorDaemon) InitSystemMonitor() bool {
	dm.SystemMonitor = mon.NewSystemMonitor(dm.LogFeeder, dm.EnableAuditd, dm.EnableHostPolicy,
		&dm.Containers, &dm.ContainersLock, &dm.ActivePidMap, &dm.ActiveHostPidMap, &dm.ActivePidMapLock, &dm.ActiveHostMap, &dm.ActiveHostMapLock)
	if dm.SystemMonitor == nil {
		return false
	}

	if err := dm.SystemMonitor.InitBPF(); err != nil {
		return false
	}

	return true
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.SystemMonitor.TraceSyscall()

	if dm.EnableHostPolicy {
		go dm.SystemMonitor.TraceHostSyscall()
	}

	go dm.SystemMonitor.UpdateLogs()

	if dm.EnableHostPolicy {
		go dm.SystemMonitor.UpdateHostLogs()
	}

	go dm.SystemMonitor.CleanUpExitedHostPids()
}

// CloseSystemMonitor Function
func (dm *KubeArmorDaemon) CloseSystemMonitor() {
	dm.SystemMonitor.DestroySystemMonitor()
}

// ================== //
// == Audit Logger == //
// ================== //

// InitAuditLogger Function
func (dm *KubeArmorDaemon) InitAuditLogger() bool {
	dm.AuditLogger = adt.NewAuditLogger(dm.LogFeeder, &dm.Containers, &dm.ContainersLock,
		&dm.ActivePidMap, &dm.ActiveHostPidMap, &dm.ActivePidMapLock, &dm.ActiveHostMap, &dm.ActiveHostMapLock)
	if dm.AuditLogger == nil {
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
func KubeArmor(gRPCPort, logPath string, enableAuditd, enableHostPolicy, enableSystemLog bool) {
	// create a daemon
	dm := NewKubeArmorDaemon(enableAuditd, enableHostPolicy, enableSystemLog)

	// initialize log feeder
	if !dm.InitLogFeeder(gRPCPort, logPath) {
		kg.Err("Failed to intialize the log feeder")
		return
	}

	// serve log feeds
	go dm.ServeLogFeeds()
	kg.Print("Started to serve gRPC-based log feeds")

	// initialize system monitor
	if !dm.InitSystemMonitor() {
		dm.LogFeeder.Err("Failed to initialize the system monitor")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}

	// monior system events
	go dm.MonitorSystemEvents()
	dm.LogFeeder.Print("Started to monitor system events")

	if dm.EnableAuditd {
		// initialize audit logger
		if !dm.InitAuditLogger() {
			dm.LogFeeder.Err("Failed to initialize the audit logger")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}

		// monitor audit logs
		go dm.MonitorAuditLogs()
		dm.LogFeeder.Print("Started to monitor audit logs")
	}

	// initialize runtime enforcer
	if !dm.InitRuntimeEnforcer() {
		dm.LogFeeder.Err("Failed to intialize the runtime enforcer")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.LogFeeder.Print("Started to protect a host and containers")

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	if K8s.InitK8sClient() {
		dm.LogFeeder.Print("Initialized the Kubernetes client")

		// watch k8s pods
		go dm.WatchK8sPods()
		dm.LogFeeder.Print("Started to monitor Pod events")

		// watch security policies
		go dm.WatchSecurityPolicies()
		dm.LogFeeder.Print("Started to monitor security policies")

		if dm.EnableHostPolicy {
			// watch host security policies
			go dm.WatchHostSecurityPolicies()
			dm.LogFeeder.Print("Started to monitor host security policies")
		}

		// get current CRI
		cr := K8s.GetContainerRuntime()

		dm.LogFeeder.Printf("Container Runtime: %s", cr)

		if strings.Contains(cr, "containerd") {
			// monitor containerd events
			go dm.MonitorContainerdEvents()
		} else if strings.Contains(cr, "docker") {
			// monitor docker events
			go dm.MonitorDockerEvents()
		}
	} else {
		dm.LogFeeder.Err("Failed to initialize the Kubernetes client")
	}

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	dm.LogFeeder.Print("Initialized KubeArmor")

	// == //

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	dm.LogFeeder.Print("Got a signal to terminate the KubeArmor")
	close(StopChan)

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
