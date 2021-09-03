// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package core

import (
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

	// node
	Node tp.Node

	// gRPC
	gRPCPort  string
	LogPath   string
	LogFilter string

	// options
	EnableKubeArmorPolicy     bool
	EnableKubeArmorHostPolicy bool

	// flag
	K8sEnabled bool

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	// K8s pods (from kubernetes)
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// endpoints
	EndPoints     []tp.EndPoint
	EndPointsLock *sync.RWMutex

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

	// logger
	Logger *fd.Feeder

	// system monitor
	SystemMonitor *mon.SystemMonitor

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon(clusterName, gRPCPort, logPath string, enableKubeArmorPolicy, enableKubeArmorHostPolicy bool) *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	if clusterName == "" {
		if val, ok := os.LookupEnv("CLUSTER_NAME"); ok {
			dm.ClusterName = val
		} else {
			dm.ClusterName = "Default"
		}
	} else {
		dm.ClusterName = clusterName
	}

	dm.gRPCPort = gRPCPort
	dm.LogPath = logPath

	dm.EnableKubeArmorPolicy = enableKubeArmorPolicy
	dm.EnableKubeArmorHostPolicy = enableKubeArmorHostPolicy

	dm.K8sEnabled = false

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.EndPoints = []tp.EndPoint{}
	dm.EndPointsLock = new(sync.RWMutex)

	dm.SecurityPolicies = []tp.SecurityPolicy{}
	dm.SecurityPoliciesLock = new(sync.RWMutex)

	dm.HostSecurityPolicies = []tp.HostSecurityPolicy{}
	dm.HostSecurityPoliciesLock = new(sync.RWMutex)

	dm.ActivePidMap = map[string]tp.PidMap{}
	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.ActiveHostMap = map[uint32]tp.PidMap{}
	dm.ActiveHostMapLock = new(sync.RWMutex)

	dm.Logger = nil
	dm.SystemMonitor = nil
	dm.RuntimeEnforcer = nil

	dm.WgDaemon = sync.WaitGroup{}

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	if dm.RuntimeEnforcer != nil {
		// close runtime enforcer
		if dm.CloseRuntimeEnforcer() {
			dm.Logger.Print("Stopped the runtime enforcer")
		}
	}

	if dm.SystemMonitor != nil {
		// close system monitor
		if dm.CloseSystemMonitor() {
			dm.Logger.Print("Stopped the system monitor")
		}
	}

	dm.Logger.Print("Terminated the KubeArmor")

	// wait for a while
	time.Sleep(time.Second * 1)

	// close logger
	if dm.CloseLogger() {
		kg.Print("Stopped the logger")
	}

	// wait for other routines
	kg.Print("Waiting for routine terminations")
	dm.WgDaemon.Wait()
}

// ============ //
// == Logger == //
// ============ //

// InitLogger Function
func (dm *KubeArmorDaemon) InitLogger() bool {
	dm.Logger = fd.NewFeeder(dm.ClusterName, dm.Node, dm.gRPCPort, dm.LogPath)
	return dm.Logger != nil
}

// ServeLogFeeds Function
func (dm *KubeArmorDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.Logger.ServeLogFeeds()
}

// CloseLogger Function
func (dm *KubeArmorDaemon) CloseLogger() bool {
	if err := dm.Logger.DestroyFeeder(); err != nil {
		kg.Print("Failed to destroy the logger")
		return false
	}
	return true
}

// ==================== //
// == System Monitor == //
// ==================== //

// InitSystemMonitor Function
func (dm *KubeArmorDaemon) InitSystemMonitor() bool {
	dm.SystemMonitor = mon.NewSystemMonitor(dm.Node, dm.Logger, &dm.Containers, &dm.ContainersLock,
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

	if dm.EnableKubeArmorPolicy {
		go dm.SystemMonitor.TraceSyscall()
		go dm.SystemMonitor.UpdateLogs()
	}

	if dm.EnableKubeArmorHostPolicy {
		go dm.SystemMonitor.TraceHostSyscall()
		go dm.SystemMonitor.UpdateHostLogs()
	}

	if dm.EnableKubeArmorPolicy || dm.EnableKubeArmorHostPolicy {
		go dm.SystemMonitor.CleanUpExitedHostPids()
	}
}

// CloseSystemMonitor Function
func (dm *KubeArmorDaemon) CloseSystemMonitor() bool {
	if err := dm.SystemMonitor.DestroySystemMonitor(); err != nil {
		dm.Logger.Err("Failed to destroy the SystemMonitor")
		return false
	}
	return true
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer() bool {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(dm.Node, dm.Logger)
	return dm.RuntimeEnforcer.EnableLSM
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() bool {
	if err := dm.RuntimeEnforcer.DestroyRuntimeEnforcer(); err != nil {
		dm.Logger.Err("Failed to destory the Enforcer")
		return false
	}
	return true
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
func KubeArmor(clusterName, gRPCPort, logPath string, enableKubeArmorPolicy, enableKubeArmorHostPolicy bool) {
	// create a daemon
	dm := NewKubeArmorDaemon(clusterName, gRPCPort, logPath, enableKubeArmorPolicy, enableKubeArmorHostPolicy)

	// == //

	// initialize kubernetes client
	if K8s.InitK8sClient() {
		kg.Print("Initialized the Kubernetes client")

		// set the flag
		dm.K8sEnabled = true

		// watch k8s nodes
		go dm.WatchK8sNodes()
		kg.Print("Started to monitor node events")

		// == //

		// wait for a while
		time.Sleep(time.Second * 1)

		for dm.Node.NodeIP == "" {
			kg.Print("The node information is not updated yet")

			// wait for a while
			time.Sleep(time.Second * 1)
		}

		dm.Node.EnableKubeArmorPolicy = enableKubeArmorPolicy
		dm.Node.EnableKubeArmorHostPolicy = enableKubeArmorHostPolicy
	} else {
		dm.Node.NodeName = kl.GetHostName()
		dm.Node.NodeIP = kl.GetExternalIPAddr()

		dm.Node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
		dm.Node.KernelVersion = strings.TrimSuffix(dm.Node.KernelVersion, "\n")

		dm.EnableKubeArmorPolicy = false

		dm.Node.EnableKubeArmorPolicy = false
		dm.Node.EnableKubeArmorHostPolicy = enableKubeArmorHostPolicy

		kg.Print("Detected no Kubernetes")
	}

	// == //

	// initialize log feeder
	if !dm.InitLogger() {
		kg.Err("Failed to intialize the log feeder")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.Logger.Print("Initialized the logger")

	// serve log feeds
	go dm.ServeLogFeeds()
	dm.Logger.Print("Started to serve gRPC-based log feeds")

	// == //

	if dm.EnableKubeArmorPolicy || dm.EnableKubeArmorHostPolicy {
		// initialize system monitor
		if !dm.InitSystemMonitor() {
			dm.Logger.Err("Failed to initialize the system monitor")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized the system monitor")

		// monior system events
		go dm.MonitorSystemEvents()
		dm.Logger.Print("Started to monitor system events")

		// == //

		// initialize runtime enforcer
		if !dm.InitRuntimeEnforcer() {
			dm.Logger.Print("Disabled the runtime enforcer since No LSM is enabled")
		} else {
			dm.Logger.Print("Initialized the runtime enforcer")

			if dm.EnableKubeArmorPolicy && !dm.EnableKubeArmorHostPolicy {
				dm.Logger.Print("Started to protect containers")
			} else if !dm.EnableKubeArmorPolicy && dm.EnableKubeArmorHostPolicy {
				dm.Logger.Print("Started to protect a host")
			} else if dm.EnableKubeArmorPolicy && dm.EnableKubeArmorHostPolicy {
				dm.Logger.Print("Started to protect a host and containers")
			}
		}
	}

	// == //

	if dm.K8sEnabled && dm.EnableKubeArmorPolicy {
		dm.Logger.Printf("Container Runtime: %s", dm.Node.ContainerRuntimeVersion)

		if strings.HasPrefix(dm.Node.ContainerRuntimeVersion, "docker") {
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
					dm.Logger.Err("Failed to monitor containers (Docker socket file is not accessible)")

					// destroy the daemon
					dm.DestroyKubeArmorDaemon()

					return
				}
			}
		} else { // containerd
			sockFile := false

			for _, candidate := range []string{"/var/run/containerd/containerd.sock", "/var/snap/microk8s/common/run/containerd.sock"} {
				if _, err := os.Stat(candidate); err == nil {
					sockFile = true
					break
				}
			}

			if sockFile {
				// monitor containerd events
				go dm.MonitorContainerdEvents()
			} else {
				dm.Logger.Err("Failed to monitor containers (Containerd socket file is not accessible)")

				// destroy the daemon
				dm.DestroyKubeArmorDaemon()

				return
			}
		}
	}

	// == //

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	if dm.K8sEnabled && dm.EnableKubeArmorPolicy {
		// watch k8s pods
		go dm.WatchK8sPods()
		dm.Logger.Print("Started to monitor Pod events")

		// watch security policies
		go dm.WatchSecurityPolicies()
		dm.Logger.Print("Started to monitor security policies")
	}

	if dm.K8sEnabled && dm.EnableKubeArmorHostPolicy {
		// watch host security policies
		go dm.WatchHostSecurityPolicies()
		dm.Logger.Print("Started to monitor host security policies")
	}

	// == //

	dm.Logger.Print("Initialized KubeArmor")

	// == //

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	dm.Logger.Print("Got a signal to terminate the KubeArmor")
	close(StopChan)

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
