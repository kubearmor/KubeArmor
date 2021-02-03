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

	// log feeder
	LogFeeder *fd.Feeder

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// container monitor
	ContainerMonitor *mon.ContainerMonitor

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

	dm.LogFeeder = nil
	dm.ContainerMonitor = nil
	dm.RuntimeEnforcer = nil

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

	if dm.ContainerMonitor != nil {
		// close container monitor
		dm.CloseContainerMonitor()
		dm.LogFeeder.Print("Stopped the container monitor")
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

// ======================= //
// == Container Monitor == //
// ======================= //

// InitContainerMonitor Function
func (dm *KubeArmorDaemon) InitContainerMonitor() bool {
	dm.ContainerMonitor = mon.NewContainerMonitor(dm.LogFeeder, &dm.Containers, &dm.ContainersLock)
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
	go dm.ContainerMonitor.MonitorAuditLogs()
	go dm.ContainerMonitor.UpdateLogs()
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

	// initialize container monitor
	if !dm.InitContainerMonitor() {
		dm.LogFeeder.Err("Failed to initialize the container monitor")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.LogFeeder.Print("Started to monitor system events")

	// monior system events (container monitor)
	go dm.MonitorSystemEvents()

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
