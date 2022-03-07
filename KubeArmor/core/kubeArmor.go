// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/policy"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"google.golang.org/grpc/reflection"

	efc "github.com/kubearmor/KubeArmor/KubeArmor/enforcer"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	pb "github.com/kubearmor/KubeArmor/protobuf"

	kvm "github.com/kubearmor/KubeArmor/KubeArmor/kvmAgent"
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
	// node
	Node tp.Node

	// flag
	K8sEnabled bool

	// K8s pods (from kubernetes)
	K8sPods     []tp.K8sPod
	K8sPodsLock *sync.RWMutex

	// containers (from docker)
	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

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

	// kvm agent
	KVMAgent *kvm.KVMAgent

	// WgDaemon Handler
	WgDaemon sync.WaitGroup
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon() *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dm.Node = tp.Node{}

	dm.K8sEnabled = false

	dm.K8sPods = []tp.K8sPod{}
	dm.K8sPodsLock = new(sync.RWMutex)

	dm.Containers = map[string]tp.Container{}
	dm.ContainersLock = new(sync.RWMutex)

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
	dm.KVMAgent = nil

	dm.WgDaemon = sync.WaitGroup{}

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	if dm.RuntimeEnforcer != nil {
		// close runtime enforcer
		if dm.CloseRuntimeEnforcer() {
			dm.Logger.Print("Stopped KubeArmor Enforcer")
		}
	}

	if dm.SystemMonitor != nil {
		// close system monitor
		if dm.CloseSystemMonitor() {
			dm.Logger.Print("Stopped KubeArmor Monitor")
		}
	}

	if dm.KVMAgent != nil {
		// close kvm agent
		if dm.CloseKVMAgent() {
			dm.Logger.Print("Stopped KVM Agent")
		}
	}

	if dm.Logger != nil {
		dm.Logger.Print("Terminated KubeArmor")
	} else {
		kg.Print("Terminated KubeArmor")
	}

	// wait for a while
	time.Sleep(time.Second * 1)

	if dm.Logger != nil {
		// close logger
		if dm.CloseLogger() {
			kg.Print("Stopped KubeArmor Logger")
		}
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
	dm.Logger = fd.NewFeeder(&dm.Node)
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
		kg.Errf("Failed to destroy KubeArmor Logger (%s)", err.Error())
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
		kg.Errf("Failed to initialize BPF (%s)", err.Error())
		return false
	}

	return true
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if cfg.GlobalCfg.Policy {
		go dm.SystemMonitor.TraceSyscall()
		go dm.SystemMonitor.UpdateLogs()
	}

	if cfg.GlobalCfg.HostPolicy {
		go dm.SystemMonitor.TraceHostSyscall()
		go dm.SystemMonitor.UpdateHostLogs()
	}

	if cfg.GlobalCfg.Policy || cfg.GlobalCfg.HostPolicy {
		go dm.SystemMonitor.CleanUpExitedHostPids()
	}
}

// CloseSystemMonitor Function
func (dm *KubeArmorDaemon) CloseSystemMonitor() bool {
	if err := dm.SystemMonitor.DestroySystemMonitor(); err != nil {
		dm.Logger.Errf("Failed to destroy KubeArmor Monitor (%s)", err.Error())
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
	return dm.RuntimeEnforcer != nil
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() bool {
	if err := dm.RuntimeEnforcer.DestroyRuntimeEnforcer(); err != nil {
		dm.Logger.Errf("Failed to destory KubeArmor Enforcer (%s)", err.Error())
		return false
	}
	return true
}

// =============== //
// == KVM Agent == //
// =============== //

// InitKVMAgent Function
func (dm *KubeArmorDaemon) InitKVMAgent() bool {
	dm.KVMAgent = kvm.NewKVMAgent(dm.ParseAndUpdateHostSecurityPolicy)
	return dm.KVMAgent != nil
}

// ConnectToKVMService Function
func (dm *KubeArmorDaemon) ConnectToKVMService() {
	go dm.KVMAgent.ConnectToKVMService()
}

// CloseKVMAgent Function
func (dm *KubeArmorDaemon) CloseKVMAgent() bool {
	if err := dm.KVMAgent.DestroyKVMAgent(); err != nil {
		dm.Logger.Errf("Failed to destory KVM Agent (%s)", err.Error())
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
func KubeArmor() {
	// create a daemon
	dm := NewKubeArmorDaemon()

	// Enable KubeArmorHostPolicy for both VM and KVMAgent and in non-k8s env
	if cfg.GlobalCfg.KVMAgent || (!cfg.GlobalCfg.K8sEnv && cfg.GlobalCfg.HostPolicy) {
		dm.Node.NodeIP = kl.GetExternalIPAddr()

		dm.Node.Annotations = map[string]string{}
		dm.HandleNodeAnnotations(&dm.Node)

		dm.Node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
		dm.Node.KernelVersion = strings.TrimSuffix(dm.Node.KernelVersion, "\n")

		dm.Node.PolicyEnabled = tp.KubeArmorPolicyEnabled

		cfg.GlobalCfg.Policy = false
		cfg.GlobalCfg.HostPolicy = true

		kg.Print("Updated the node information")

	} else if K8s.InitK8sClient() {
		kg.Print("Initialized Kubernetes client")

		// set the flag
		dm.K8sEnabled = true

		// watch k8s nodes
		go dm.WatchK8sNodes()
		kg.Print("Started to monitor node events")

		// == //

		// wait for a while
		time.Sleep(time.Second * 1)

		if dm.Node.NodeIP == "" {
			for timeout := 0; timeout <= 60; timeout++ {
				if dm.Node.NodeIP != "" {
					break
				}

				if dm.Node.NodeIP == "" && timeout == 60 {
					kg.Print("The node information is not available, terminating KubeArmor")

					// destroy the daemon
					dm.DestroyKubeArmorDaemon()

					return
				}

				kg.Print("The node information is not available")

				// wait for a while
				time.Sleep(time.Second * 1)
			}
		}

	}

	// == //

	// initialize log feeder
	if !dm.InitLogger() {
		kg.Err("Failed to intialize KubeArmor Logger")

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.Logger.Print("Initialized KubeArmor Logger")

	// == //

	if cfg.GlobalCfg.Policy || cfg.GlobalCfg.HostPolicy {
		// initialize system monitor
		if !dm.InitSystemMonitor() {
			dm.Logger.Err("Failed to initialize KubeArmor Monitor")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized KubeArmor Monitor")

		// monior system events
		go dm.MonitorSystemEvents()
		dm.Logger.Print("Started to monitor system events")

		// == //

		// initialize runtime enforcer
		if !dm.InitRuntimeEnforcer() {
			dm.Logger.Print("Disabled KubeArmor Enforcer since No LSM is enabled")
		} else {
			dm.Logger.Print("Initialized KubeArmor Enforcer")

			if cfg.GlobalCfg.Policy && !cfg.GlobalCfg.HostPolicy {
				dm.Logger.Print("Started to protect containers")
			} else if !cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy {
				dm.Logger.Print("Started to protect a host")
			} else if cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy {
				dm.Logger.Print("Started to protect a host and containers")
			}
		}
	}

	// == //

	if dm.K8sEnabled && cfg.GlobalCfg.Policy {
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

			for _, candidate := range []string{"/var/run/containerd/containerd.sock", "/var/snap/microk8s/common/run/containerd.sock", "/run/k3s/containerd/containerd.sock"} {
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

	if dm.K8sEnabled && cfg.GlobalCfg.Policy {
		// watch k8s pods
		go dm.WatchK8sPods()
		dm.Logger.Print("Started to monitor Pod events")

		// watch security policies
		go dm.WatchSecurityPolicies()
		dm.Logger.Print("Started to monitor security policies")
	}

	if dm.K8sEnabled && cfg.GlobalCfg.HostPolicy {
		// watch host security policies
		go dm.WatchHostSecurityPolicies()
		dm.Logger.Print("Started to monitor host security policies")
	}

	if !dm.K8sEnabled && cfg.GlobalCfg.HostPolicy {
		policyService := &policy.ServiceServer{}
		policyService.UpdateHostPolicy = dm.ParseAndUpdateHostSecurityPolicy

		pb.RegisterPolicyServiceServer(dm.Logger.LogServer, policyService)
		reflection.Register(dm.Logger.LogServer)

		dm.Logger.Print("Started to monitor host security policies on gRPC")
	}

	// serve log feeds
	go dm.ServeLogFeeds()
	dm.Logger.Print("Started to serve gRPC-based log feeds")

	// == //

	dm.Logger.Print("Initialized KubeArmor")

	// == //

	if !cfg.GlobalCfg.K8sEnv && (cfg.GlobalCfg.KVMAgent || cfg.GlobalCfg.HostPolicy) {
		// Restore and apply all kubearmor host security policies
		dm.restoreKubeArmorHostPolicies()
	}

	// == //

	// Init KvmAgent
	if cfg.GlobalCfg.KVMAgent {
		// initialize kvm agent
		if !dm.InitKVMAgent() {
			dm.Logger.Err("Failed to initialize KVM Agent")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized KVM Agent")

		// connect to KVM Service
		go dm.ConnectToKVMService()
		dm.Logger.Print("Started to keep the connection to KVM Service")
	}

	// == //

	if !cfg.GlobalCfg.CoverageTest {
		// listen for interrupt signals
		sigChan := GetOSSigChannel()
		<-sigChan
		dm.Logger.Print("Got a signal to terminate KubeArmor")
		close(StopChan)
	}

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
