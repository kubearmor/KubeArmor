// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	efc "github.com/kubearmor/KubeArmor/KubeArmor/enforcer"
	edt "github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
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
	// cluster
	ClusterName string

	// gRPC
	gRPCPort  string
	LogPath   string
	LogFilter string

	// options
	EnableHostPolicy     bool
	EnableEnforcerPerPod bool

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	// endpoints
	EndPoints     []tp.EndPoint
	EndPointsLock *sync.RWMutex

	// K8s pods
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// Host Security policies
	HostSecurityPolicies     []tp.HostSecurityPolicy
	HostSecurityPoliciesLock *sync.RWMutex

	// K8s Audit policies
	K8sAuditPolicies     []tp.K8sKubeArmorAuditPolicy
	K8sAuditPoliciesLock *sync.RWMutex

	// Audit policies
	AuditPolicies     []tp.KubeArmorAuditPolicy
	AuditPoliciesLock *sync.RWMutex

	// Macros (namespace -> macro)
	KubeArmorMacrosMap  tp.KubeArmorMacros
	KubeArmorMacrosLock *sync.RWMutex

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

	// event auditor
	EventAuditor *edt.EventAuditor

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon(clusterName, gRPCPort, logPath, logFilter string, enableHostPolicy, enableEnforcerPerPod bool) *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	if clusterName == "" {
		metadata := false

		if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				if clusterStr, err := kl.GetCommandOutputWithErr("curl", []string{"http://metadata/computeMetadata/v1/instance/attributes/cluster-name", "-H", "'Metadata-Flavor: Google'"}); err == nil {
					dm.ClusterName = clusterStr
					metadata = true
				}
			}
		}

		if !metadata {
			if val, ok := os.LookupEnv("CLUSTER_NAME"); ok {
				dm.ClusterName = val
			} else {
				dm.ClusterName = "Default"
			}
		}
	} else {
		dm.ClusterName = clusterName
	}

	dm.gRPCPort = gRPCPort
	dm.LogPath = logPath
	dm.LogFilter = logFilter

	dm.EnableHostPolicy = enableHostPolicy
	dm.EnableEnforcerPerPod = enableEnforcerPerPod

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

	dm.EndPoints = []tp.EndPoint{}
	dm.EndPointsLock = new(sync.RWMutex)

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)

	dm.HostSecurityPolicies = []tp.HostSecurityPolicy{}
	dm.HostSecurityPoliciesLock = new(sync.RWMutex)

	dm.K8sAuditPolicies = []tp.K8sKubeArmorAuditPolicy{}
	dm.K8sAuditPoliciesLock = new(sync.RWMutex)

	dm.AuditPolicies = []tp.KubeArmorAuditPolicy{}
	dm.AuditPoliciesLock = new(sync.RWMutex)

	dm.KubeArmorMacrosMap = tp.KubeArmorMacros{}
	dm.KubeArmorMacrosLock = new(sync.RWMutex)

	dm.ActivePidMap = map[string]tp.PidMap{}
	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.ActiveHostMap = map[uint32]tp.PidMap{}
	dm.ActiveHostMapLock = new(sync.RWMutex)

	dm.LogFeeder = nil
	dm.SystemMonitor = nil
	dm.RuntimeEnforcer = nil
	dm.EventAuditor = nil

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

	if dm.EventAuditor != nil {
		// close event auditor
		dm.CloseEventAuditor()
		dm.LogFeeder.Print("Stopped the event auditor")
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
func (dm *KubeArmorDaemon) InitLogFeeder() bool {
	dm.LogFeeder = fd.NewFeeder(dm.ClusterName, dm.gRPCPort, dm.LogPath, dm.LogFilter, dm.EnableHostPolicy)
	return dm.LogFeeder != nil
}

// ServeLogFeeds Function
func (dm *KubeArmorDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.LogFeeder.ServeLogFeeds()
}

// CloseLogFeeder Function
func (dm *KubeArmorDaemon) CloseLogFeeder() {
	if err := dm.LogFeeder.DestroyFeeder(); err != nil {
		fmt.Println("Failed to destroy the Feeder")
	}
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer() bool {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(dm.LogFeeder, dm.EnableHostPolicy)
	return dm.RuntimeEnforcer.IsEnabled()
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() {
	if err := dm.RuntimeEnforcer.DestroyRuntimeEnforcer(); err != nil {
		fmt.Println("Failed to destory the Enforcer")
	}
}

// ==================== //
// == System Monitor == //
// ==================== //

// InitSystemMonitor Function
func (dm *KubeArmorDaemon) InitSystemMonitor() bool {
	dm.SystemMonitor = mon.NewSystemMonitor(dm.LogFeeder, dm.EnableHostPolicy, &dm.Containers, &dm.ContainersLock,
		&dm.ActivePidMap, &dm.ActiveHostPidMap, &dm.ActivePidMapLock, &dm.ActiveHostMap, &dm.ActiveHostMapLock)
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
	if err := dm.SystemMonitor.DestroySystemMonitor(); err != nil {
		fmt.Println("Failed to destroy the SystemMonitor")
	}
}

// =================== //
// == Event Auditor == //
// =================== //

// InitEventAuditor Function
func (dm *KubeArmorDaemon) InitEventAuditor() bool {
	dm.EventAuditor = edt.NewEventAuditor(dm.LogFeeder)
	return dm.EventAuditor != nil
}

// CloseEventAuditor Function
func (dm *KubeArmorDaemon) CloseEventAuditor() {
	if err := dm.EventAuditor.DestroyEventAuditor(); err != nil {
		fmt.Println("Failed to destory the EventAuditor")
	}
}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
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
func KubeArmor(clusterName, gRPCPort, logPath, logFilter string, enableHostPolicy, enableEnforcerPerPod bool) {
	// create a daemon
	dm := NewKubeArmorDaemon(clusterName, gRPCPort, logPath, logFilter, enableHostPolicy, enableEnforcerPerPod)

	// initialize log feeder
	if !dm.InitLogFeeder() {
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

	// initialize runtime enforcer
	if !dm.InitRuntimeEnforcer() {
		dm.LogFeeder.Print("Disabled the runtime enforcer since No LSM is enabled")
	} else {
		if dm.EnableHostPolicy {
			dm.LogFeeder.Print("Started to protect a host and containers")
		} else {
			dm.LogFeeder.Print("Started to protect containers")
		}
	}

	// initialize event auditor
	if !dm.InitEventAuditor() {
		dm.LogFeeder.Err("Failed to initialize the event auditor")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.LogFeeder.Print("Started to audit system events")

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

		if dm.EventAuditor != nil {
			// watch audit policies
			go dm.WatchAuditPolicies()
			dm.LogFeeder.Print("Started to monitor audit policies")

			// watch macros
			go dm.WatchKubeArmorMacro()
			dm.LogFeeder.Print("Started to monitor kubearmor macros")
		}

		// get current CRI
		cr := K8s.GetContainerRuntime()

		dm.LogFeeder.Printf("Container Runtime: %s", cr)

		if strings.HasPrefix(cr, "docker") {
			sockFile := false

			for _, candidate := range []string{"/var/run/docker.sock"} {
				if _, err := os.Stat(candidate); err == nil {
					sockFile = true
					break
				}
			}

			if sockFile {
				// update already deployed containers
				dm.GetAlreadyDeployedDockerContainers()

				// monitor docker events
				go dm.MonitorDockerEvents()
			} else {
				for _, candidate := range []string{"/var/run/containerd/containerd.sock"} {
					if _, err := os.Stat(candidate); err == nil {
						sockFile = true
						break
					}
				}

				if sockFile {
					// monitor containerd events
					go dm.MonitorContainerdEvents()
				} else {
					dm.LogFeeder.Err("Failed to monitor containers (Docker socket file is not accessible)")

					// destroy the daemon
					dm.DestroyKubeArmorDaemon()

					return
				}
			}
		} else { // containerd
			sockFile := false

			for _, candidate := range []string{"/var/run/containerd/containerd.sock"} {
				if _, err := os.Stat(candidate); err == nil {
					sockFile = true
					break
				}
			}

			if sockFile {
				// monitor containerd events
				go dm.MonitorContainerdEvents()
			} else {
				dm.LogFeeder.Err("Failed to monitor containers (Containerd socket file is not accessible)")

				// destroy the daemon
				dm.DestroyKubeArmorDaemon()

				return
			}
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
