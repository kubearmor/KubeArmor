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

	// Host Security policies
	HostSecurityPolicies     []tp.HostSecurityPolicy
	HostSecurityPoliciesLock *sync.Mutex

	// container id -> pid
	ActivePidMap     map[string]tp.PidMap
	ActivePidMapLock *sync.Mutex

	// container id -> host pid
	ActiveHostPidMap     map[string]tp.PidMap
	ActiveHostPidMapLock *sync.Mutex

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
func NewKubeArmorDaemon() *KubeArmorDaemon {
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

	dm.HostSecurityPolicies = []tp.HostSecurityPolicy{}
	dm.HostSecurityPoliciesLock = &sync.Mutex{}

	dm.ActivePidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = &sync.Mutex{}

	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActiveHostPidMapLock = &sync.Mutex{}

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

	if dm.AuditLogger != nil {
		// close audit logger
		dm.CloseAuditLogger()
		dm.LogFeeder.Print("Stopped the audit logger")
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
func (dm *KubeArmorDaemon) InitLogFeeder(port, output string) bool {
	dm.LogFeeder = fd.NewFeeder(port, output)
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
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(dm.LogFeeder)
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
	dm.SystemMonitor = mon.NewSystemMonitor(dm.LogFeeder, &dm.Containers, &dm.ContainersLock, &dm.ActivePidMap, &dm.ActivePidMapLock, &dm.ActiveHostPidMap, &dm.ActiveHostPidMapLock)
	if dm.SystemMonitor == nil {
		return false
	}

	if err := dm.SystemMonitor.InitBPF(dm.HomeDir); err != nil {
		return false
	}

	return true
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.SystemMonitor.TraceSyscall()
	go dm.SystemMonitor.UpdateLogs()
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
	dm.AuditLogger = adt.NewAuditLogger(dm.LogFeeder, dm.HomeDir, &dm.Containers, &dm.ContainersLock, &dm.ActivePidMap, &dm.ActivePidMapLock, &dm.ActiveHostPidMap, &dm.ActiveHostPidMapLock)
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
func KubeArmor(port, output string) {
	// create a daemon
	dm := NewKubeArmorDaemon()

	// initialize log feeder
	if !dm.InitLogFeeder(port, output) {
		kg.Err("Failed to intialize the log feeder")
		return
	}
	kg.Print("Initialized the log feeder")

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
	dm.LogFeeder.Print("Started to monitor system events")

	// monior system events
	go dm.MonitorSystemEvents()

	// initialize audit logger
	if !dm.InitAuditLogger() {
		dm.LogFeeder.Err("Failed to initialize the audit logger")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.LogFeeder.Print("Started to monitor audit logger")

	// monitor audit logs
	go dm.MonitorAuditLogs()

	// initialize runtime enforcer
	if !dm.InitRuntimeEnforcer() {
		dm.LogFeeder.Err("Failed to intialize the runtime enforcer")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.LogFeeder.Print("Started to protect containers")

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	if K8s.InitK8sClient() {
		dm.LogFeeder.Print("Initialized the Kubernetes client")

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

		// watch k8s pods
		go dm.WatchK8sPods()
		dm.LogFeeder.Print("Started to monitor Pod events")

		// watch security policies
		go dm.WatchSecurityPolicies()
		dm.LogFeeder.Print("Started to monitor security policies")

		// watch host security policies
		go dm.WatchHostSecurityPolicies()
		dm.LogFeeder.Print("Started to monitor host security policies")
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
