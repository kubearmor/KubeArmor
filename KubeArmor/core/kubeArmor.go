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

	LogFilter string

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
	dm.Logger = fd.NewFeeder(cfg.GlobalCfg.Cluster, &dm.Node, cfg.GlobalCfg.Grpc, cfg.GlobalCfg.LogPath)
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
		kg.Print("Failed to destroy KubeArmor Logger")
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
		kg.Err(err.Error())
		return false
	}

	return true
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if cfg.PodBasedPolicyEnabled() {
		go dm.SystemMonitor.TraceSyscall()
		go dm.SystemMonitor.UpdateLogs()
	}

	if cfg.HostBasedPolicyEnabled() {
		go dm.SystemMonitor.TraceHostSyscall()
		go dm.SystemMonitor.UpdateHostLogs()
	}

	if cfg.PolicyEnabled() {
		go dm.SystemMonitor.CleanUpExitedHostPids()
	}
}

// CloseSystemMonitor Function
func (dm *KubeArmorDaemon) CloseSystemMonitor() bool {
	if err := dm.SystemMonitor.DestroySystemMonitor(); err != nil {
		dm.Logger.Err("Failed to destroy KubeArmor Monitor")
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
		dm.Logger.Err("Failed to destory KubeArmor Enforcer")
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
		dm.Logger.Err("Failed to destory KVM Agent")
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

	// initialize kubernetes client
	if K8s.InitK8sClient() {
		kg.Print("Initialized Kubernetes client")

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

	} else {
		dm.Node.NodeName = kl.GetHostName()
		dm.Node.NodeIP = kl.GetExternalIPAddr()

		dm.Node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
		dm.Node.KernelVersion = strings.TrimSuffix(dm.Node.KernelVersion, "\n")

		cfg.GlobalCfg.Policy = false
		cfg.GlobalCfg.Seccomp = false
		cfg.GlobalCfg.HostPolicy = true

		dm.Node.PolicyEnabled = tp.KubeArmorPolicyEnabled

		dm.Node.Annotations = map[string]string{}

		// update annotations
		kg.Printf("using host visibility [%s]", cfg.GlobalCfg.HostVisibility)
		dm.Node.Annotations["kubearmor-visibility"] = cfg.GlobalCfg.HostVisibility
		HandleNodeAnnotations(&dm.Node)

		kg.Print("Detected no Kubernetes")
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

	if cfg.PolicyEnabled() {
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
			dm.Logger.Printf("Initialized KubeArmor Policy=%v, Seccomp=%v, hostPolicy=%v",
				cfg.GlobalCfg.Policy, cfg.GlobalCfg.Seccomp, cfg.GlobalCfg.HostPolicy)
		}
	}

	// == //

	if dm.K8sEnabled && cfg.PodBasedPolicyEnabled() {
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
	if cfg.PodBasedPolicyEnabled() {
		// watch k8s pods
		go dm.WatchK8sPods()
	}

	if dm.K8sEnabled && cfg.GlobalCfg.Policy {
		// watch security policies
		go dm.WatchSecurityPolicies()
		dm.Logger.Print("Started to monitor security policies")
	}

	if dm.K8sEnabled && cfg.GlobalCfg.Seccomp {
		// watch security policies
		// TODO go dm.WatchSecurityPolicies()
		dm.Logger.Print("Started to monitor kscmp security policies")
	}

	if dm.K8sEnabled && cfg.GlobalCfg.HostPolicy {
		// watch host security policies
		go dm.WatchHostSecurityPolicies()
		dm.Logger.Print("Started to monitor host security policies")
	}

	if !dm.K8sEnabled && cfg.GlobalCfg.HostPolicy {
		dm.Logger.Print("Monitoring host security policies on GRPC")
		policyService := &policy.ServiceServer{}
		policyService.UpdateHostPolicy = dm.ParseAndUpdateHostSecurityPolicy
		pb.RegisterPolicyServiceServer(dm.Logger.LogServer, policyService)
	}

	// serve log feeds
	reflection.Register(dm.Logger.LogServer)
	go dm.ServeLogFeeds()
	dm.Logger.Print("Started to serve gRPC-based log feeds")

	// == //

	dm.Logger.Print("Initialized KubeArmor")

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

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	dm.Logger.Print("Got a signal to terminate KubeArmor")
	close(StopChan)

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}
