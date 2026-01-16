// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/policy"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/client-go/tools/cache"

	efc "github.com/kubearmor/KubeArmor/KubeArmor/enforcer"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	kvm "github.com/kubearmor/KubeArmor/KubeArmor/kvmAgent"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	dvc "github.com/kubearmor/KubeArmor/KubeArmor/usbDeviceHandler"
	pb "github.com/kubearmor/KubeArmor/protobuf"
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
	Node     tp.Node
	NodeLock *sync.RWMutex

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

	// Owner Info
	OwnerInfo     map[string]tp.PodOwner
	OwnerInfoLock *sync.RWMutex

	// Security policies
	SecurityPolicies     []tp.SecurityPolicy
	SecurityPoliciesLock *sync.RWMutex

	// Host Security policies
	HostSecurityPolicies     []tp.HostSecurityPolicy
	HostSecurityPoliciesLock *sync.RWMutex

	//DefaultPosture (namespace -> postures)
	DefaultPostures     map[string]tp.DefaultPosture
	DefaultPosturesLock *sync.Mutex

	// pid map
	ActiveHostPidMap map[string]tp.PidMap
	ActivePidMapLock *sync.RWMutex

	// logger
	Logger *fd.Feeder

	// system monitor
	SystemMonitor *mon.SystemMonitor

	// runtime enforcer
	RuntimeEnforcer *efc.RuntimeEnforcer

	// presets
	Presets *presets.Preset

	// kvm agent
	KVMAgent *kvm.KVMAgent

	// state agent
	StateAgent *state.StateAgent

	// WgDaemon Handler
	WgDaemon sync.WaitGroup

	// system monitor lock
	MonitorLock *sync.RWMutex

	// health-server
	GRPCHealthServer *health.Server

	// USB device handler
	USBDeviceHandler *dvc.USBDeviceHandler
}

// NewKubeArmorDaemon Function
func NewKubeArmorDaemon() *KubeArmorDaemon {
	dm := new(KubeArmorDaemon)

	dm.Node = tp.Node{}
	dm.NodeLock = new(sync.RWMutex)

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

	dm.DefaultPostures = map[string]tp.DefaultPosture{}
	dm.DefaultPosturesLock = new(sync.Mutex)

	dm.ActiveHostPidMap = map[string]tp.PidMap{}
	dm.ActivePidMapLock = new(sync.RWMutex)

	dm.Logger = nil
	dm.SystemMonitor = nil
	dm.RuntimeEnforcer = nil
	dm.KVMAgent = nil
	dm.USBDeviceHandler = nil

	dm.WgDaemon = sync.WaitGroup{}

	dm.MonitorLock = new(sync.RWMutex)

	dm.OwnerInfo = map[string]tp.PodOwner{}
	dm.OwnerInfoLock = new(sync.RWMutex)

	return dm
}

// DestroyKubeArmorDaemon Function
func (dm *KubeArmorDaemon) DestroyKubeArmorDaemon() {
	close(StopChan)

	if dm.RuntimeEnforcer != nil {
		// close runtime enforcer
		if err := dm.CloseRuntimeEnforcer(); err != nil {
			dm.Logger.Errf("Failed to stop KubeArmor Enforcer: %s", err.Error())
		} else {
			dm.Logger.Print("Stopped KubeArmor Enforcer")
		}
	}

	if dm.SystemMonitor != nil {
		// close system monitor
		if err := dm.CloseSystemMonitor(); err != nil {
			dm.Logger.Errf("Failed to stop KubeArmor Monitor: %s", err.Error())
		} else {
			dm.Logger.Print("Stopped KubeArmor Monitor")
		}
	}

	if dm.KVMAgent != nil {
		// close kvm agent
		if err := dm.CloseKVMAgent(); err != nil {
			dm.Logger.Errf("Failed to stop KVM Agent: %s", err.Error())
		} else {
			dm.Logger.Print("Stopped KVM Agent")
		}
	}

	if dm.USBDeviceHandler != nil {
		//close USB device handler
		if dm.CloseUSBDeviceHandler() {
			dm.Logger.Print("Stopped USB Device Handler")
		}
	}

	if dm.Logger != nil {
		dm.Logger.Print("Terminated KubeArmor")
	} else {
		kg.Print("Terminated KubeArmor")
	}

	if dm.StateAgent != nil {
		//go dm.StateAgent.PushNodeEvent(dm.Node, state.EventDeleted)
		if err := dm.CloseStateAgent(); err != nil {
			kg.Errf("Failed to destroy StateAgent: %s", err.Error())
		} else {
			kg.Print("Destroyed StateAgent")
		}
	}

	// wait for a while
	time.Sleep(time.Second * 1)

	if dm.Logger != nil {
		// close logger
		if err := dm.CloseLogger(); err != nil {
			kg.Errf("Failed to stop KubeArmor Logger: %s", err.Error())
		} else {
			kg.Print("Stopped KubeArmor Logger")
		}
	}

	// wait for other routines
	kg.Print("Waiting for routine terminations")
	dm.WgDaemon.Wait()

	// delete pid file
	if _, err := os.Stat(cfg.PIDFilePath); err == nil {
		kg.Print("Deleting PID file")

		err := os.Remove(cfg.PIDFilePath)
		if err != nil {
			kg.Errf("Failed to delete PID file")
		}
	}
}

// ============ //
// == Logger == //
// ============ //

// InitLogger Function
func (dm *KubeArmorDaemon) InitLogger() error {
	dm.Logger = fd.NewFeeder(&dm.Node, &dm.NodeLock)
	if dm.Logger == nil {
		return fmt.Errorf("failed to create new feeder")
	}
	return nil
}

// ServeLogFeeds Function
func (dm *KubeArmorDaemon) ServeLogFeeds() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	go dm.Logger.ServeLogFeeds()
}

// CloseLogger Function
func (dm *KubeArmorDaemon) CloseLogger() error {
	if err := dm.Logger.DestroyFeeder(); err != nil {
		return fmt.Errorf("failed to destroy KubeArmor Logger: %w", err)
	}
	return nil
}

// ==================== //
// == System Monitor == //
// ==================== //

// InitSystemMonitor Function
func (dm *KubeArmorDaemon) InitSystemMonitor() error {
	dm.SystemMonitor = mon.NewSystemMonitor(&dm.Node, &dm.NodeLock, dm.Logger, &dm.Containers, &dm.ContainersLock, &dm.ActiveHostPidMap, &dm.ActivePidMapLock, &dm.MonitorLock)
	if dm.SystemMonitor == nil {
		return fmt.Errorf("failed to create new system monitor")
	}

	if err := dm.SystemMonitor.InitBPF(); err != nil {
		return fmt.Errorf("failed to initialize BPF: %w", err)
	}

	return nil
}

// MonitorSystemEvents Function
func (dm *KubeArmorDaemon) MonitorSystemEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if cfg.GlobalCfg.Policy || cfg.GlobalCfg.HostPolicy {
		go dm.SystemMonitor.TraceSyscall()
		go dm.SystemMonitor.UpdateLogs()
		go dm.SystemMonitor.CleanUpExitedHostPids()
	}
}

// CloseSystemMonitor Function
func (dm *KubeArmorDaemon) CloseSystemMonitor() error {
	if err := dm.SystemMonitor.DestroySystemMonitor(); err != nil {
		return fmt.Errorf("failed to destroy KubeArmor Monitor: %w", err)
	}
	return nil
}

// ====================== //
// == Runtime Enforcer == //
// ====================== //

// InitRuntimeEnforcer Function
func (dm *KubeArmorDaemon) InitRuntimeEnforcer(pinpath string) error {
	dm.RuntimeEnforcer = efc.NewRuntimeEnforcer(dm.Node, pinpath, dm.Logger, dm.SystemMonitor)
	if dm.RuntimeEnforcer == nil {
		return fmt.Errorf("failed to create runtime enforcer")
	}
	return nil
}

// CloseRuntimeEnforcer Function
func (dm *KubeArmorDaemon) CloseRuntimeEnforcer() error {
	if err := dm.RuntimeEnforcer.DestroyRuntimeEnforcer(); err != nil {
		return fmt.Errorf("failed to destroy KubeArmor Enforcer: %w", err)
	}
	return nil
}

// ======================== //
// == USB Device Handler == //
// ======================== //

// InitUSBDeviceHandler Function
func (dm *KubeArmorDaemon) InitUSBDeviceHandler() bool {
	dm.USBDeviceHandler = dvc.NewUSBDeviceHandler(dm.Logger)
	return dm.USBDeviceHandler != nil
}

// CloseUSBDeviceHandler Function
func (dm *KubeArmorDaemon) CloseUSBDeviceHandler() bool {
	if err := dm.USBDeviceHandler.DestroyUSBDeviceHandler(); err != nil {
		dm.Logger.Errf("Failed to destroy KubeArmor USB Device Handler (%s)", err.Error())
		return false
	}
	return true
}

// ============= //
// == Presets == //
// ============= //

// InitPresets Function
func (dm *KubeArmorDaemon) InitPresets(logger *fd.Feeder, monitor *mon.SystemMonitor) error {
	dm.Presets = presets.NewPreset(dm.Logger, dm.SystemMonitor)
	if dm.Presets == nil {
		return fmt.Errorf("failed to create presets")
	}
	return nil
}

// ClosePresets Function
func (dm *KubeArmorDaemon) ClosePresets() error {
	if err := dm.Presets.Destroy(); err != nil {
		return fmt.Errorf("failed to destroy preset: %w", err)
	}
	return nil
}

// =============== //
// == KVM Agent == //
// =============== //

// InitKVMAgent Function
func (dm *KubeArmorDaemon) InitKVMAgent() error {
	dm.KVMAgent = kvm.NewKVMAgent(dm.ParseAndUpdateHostSecurityPolicy)
	if dm.KVMAgent == nil {
		return fmt.Errorf("failed to create KVM agent")
	}
	return nil
}

// ConnectToKVMService Function
func (dm *KubeArmorDaemon) ConnectToKVMService() {
	go dm.KVMAgent.ConnectToKVMService()
}

// CloseKVMAgent Function
func (dm *KubeArmorDaemon) CloseKVMAgent() error {
	if err := dm.KVMAgent.DestroyKVMAgent(); err != nil {
		return fmt.Errorf("failed to destroy KVM Agent: %w", err)
	}
	return nil
}

// ================= //
// == State Agent == //
// ================= //

// InitStateAgent Function
func (dm *KubeArmorDaemon) InitStateAgent() error {
	dm.StateAgent = state.NewStateAgent(&dm.Node, dm.NodeLock, dm.Containers, dm.ContainersLock)
	if dm.StateAgent == nil {
		return fmt.Errorf("failed to create state agent")
	}
	return nil
}

// CloseStateAgent Function
func (dm *KubeArmorDaemon) CloseStateAgent() error {
	if err := dm.StateAgent.DestroyStateAgent(); err != nil {
		return fmt.Errorf("failed to destroy State Agent: %w", err)
	}
	return nil
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

// =================== //
// == Health Server == //
// =================== //
func (dm *KubeArmorDaemon) SetHealthStatus(serviceName string, healthStatus grpc_health_v1.HealthCheckResponse_ServingStatus) error {
	if dm.GRPCHealthServer != nil {
		dm.GRPCHealthServer.SetServingStatus(serviceName, healthStatus)
		return nil
	}

	return fmt.Errorf("GRPC health server is not initialized")
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

		dm.NodeLock.Lock()

		dm.Node.NodeName = cfg.GlobalCfg.Host
		dm.Node.NodeIP = kl.GetExternalIPAddr()

		// add identity for matching node selector
		dm.Node.Labels = make(map[string]string)
		dm.Node.Labels["kubearmor.io/hostname"] = dm.Node.NodeName

		dm.Node.Identities = append(dm.Node.Identities, "kubearmor.io/hostname"+"="+dm.Node.NodeName)

		dm.Node.Annotations = map[string]string{}
		dm.HandleNodeAnnotations(&dm.Node)

		hostInfo := kl.GetCommandOutputWithoutErr("hostnamectl", []string{})
		for line := range strings.SplitSeq(hostInfo, "\n") {
			if strings.Contains(line, "Machine ID") {
				dm.Node.NodeID = strings.Split(line, ": ")[1]
			}
			if strings.Contains(line, "Operating System") {
				dm.Node.OSImage = strings.Split(line, ": ")[1]
			}
		}

		dm.Node.LastUpdatedAt = kl.GetBootTime()

		dm.Node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
		dm.Node.KernelVersion = strings.TrimSuffix(dm.Node.KernelVersion, "\n")

		dm.WatchConfigChanges()

		dm.NodeLock.Unlock()

	} else if cfg.GlobalCfg.K8sEnv {
		if err := K8s.InitK8sClient(); err != nil {
			kg.Errf("Failed to initialize Kubernetes client: %v", err)

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}

		kg.Print("Initialized Kubernetes client")

		// set the flag
		dm.K8sEnabled = true

		// watch k8s nodes
		go dm.WatchK8sNodes()
		kg.Print("Started to monitor node events")

		// == //

		// wait for a while
		time.Sleep(time.Second * 1)

		for timeout := 0; timeout <= 60; timeout++ {

			// read node information
			dm.NodeLock.RLock()
			nodeIP := dm.Node.NodeIP
			dm.NodeLock.RUnlock()

			if nodeIP != "" {
				break
			}

			if nodeIP == "" && timeout == 60 {
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

	protectedID := func(id, key string) string {
		mac := hmac.New(sha256.New, []byte(id))
		mac.Write([]byte(key))
		return hex.EncodeToString(mac.Sum(nil))
	}

	if dm.Node.NodeID == "" {
		id, _ := os.ReadFile(cfg.GlobalCfg.MachineIDPath)
		dm.Node.NodeID = strings.TrimSuffix(string(id), "\n")
	}
	dm.Node.NodeID = protectedID(dm.Node.NodeID, dm.Node.NodeName)

	kg.Printf("Node Name: %s", dm.Node.NodeName)
	kg.Printf("Node IP: %s", dm.Node.NodeIP)
	kg.Printf("Node ID: %s", dm.Node.NodeID)
	if dm.K8sEnabled {
		kg.Printf("Node Annotations: %v", dm.Node.Annotations)
	}

	kg.Printf("OS Image: %s", dm.Node.OSImage)
	kg.Printf("Kernel Version: %s", dm.Node.KernelVersion)
	if dm.K8sEnabled {
		kg.Printf("Kubelet Version: %s", dm.Node.KubeletVersion)
		kg.Printf("Container Runtime: %s", dm.Node.ContainerRuntimeVersion)
	}
	// == //

	// initialize log feeder
	if err := dm.InitLogger(); err != nil {
		kg.Errf("Failed to initialize KubeArmor Logger: %v", err)

		// destroy the daemon
		dm.DestroyKubeArmorDaemon()

		return
	}
	dm.Logger.Print("Initialized KubeArmor Logger")

	// == //

	// health server
	if dm.Logger.LogServer != nil {
		dm.GRPCHealthServer = health.NewServer()
		grpc_health_v1.RegisterHealthServer(dm.Logger.LogServer, dm.GRPCHealthServer)
	}

	// Init StateAgent
	if !dm.K8sEnabled && cfg.GlobalCfg.StateAgent {
		dm.NodeLock.Lock()
		dm.Node.ClusterName = cfg.GlobalCfg.Cluster
		dm.NodeLock.Unlock()

		// initialize state agent
		if err := dm.InitStateAgent(); err != nil {
			dm.Logger.Errf("Failed to initialize State Agent Server: %s", err.Error())

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized State Agent Server")

		pb.RegisterStateAgentServer(dm.Logger.LogServer, dm.StateAgent)
		if err := dm.SetHealthStatus(pb.StateAgent_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
			dm.Logger.Warnf("Failed to set health status for StateAgent: %v", err)
		}
	}

	if dm.StateAgent != nil {
		go dm.StateAgent.PushNodeEvent(dm.Node, state.EventAdded)
	}

	// == //

	// Containerized workloads with Host
	if cfg.GlobalCfg.Policy || cfg.GlobalCfg.HostPolicy {
		// initialize system monitor
		if err := dm.InitSystemMonitor(); err != nil {
			dm.Logger.Errf("Failed to initialize KubeArmor Monitor: %v", err)

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized KubeArmor Monitor")

		// monitor system events
		go dm.MonitorSystemEvents()
		dm.Logger.Print("Started to monitor system events")

		// initialize runtime enforcer
		if err := dm.InitRuntimeEnforcer(dm.SystemMonitor.PinPath); err != nil {
			dm.Logger.Printf("Disabled KubeArmor Enforcer: %s", err.Error())
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

		// initialize presets
		if err := dm.InitPresets(dm.Logger, dm.SystemMonitor); err != nil {
			dm.Logger.Printf("Disabled Presets: %s", err.Error())
		} else {
			dm.Logger.Print("Initialized Presets")
		}
	}

	enableContainerPolicy := true

	dm.SystemMonitor.Logger.ContainerNsKey = make(map[string]common.OuterKey)

	// Un-orchestrated workloads
	if !dm.K8sEnabled && cfg.GlobalCfg.Policy {
		// Check if cri socket set, if not then auto detect
		if !cfg.GlobalCfg.UseOCIHooks {
			if cfg.GlobalCfg.CRISocket == "" {
				if kl.GetCRISocket("") == "" {
					dm.Logger.Warnf("Error while looking for CRI socket file")
					enableContainerPolicy = false
				} else {
					cfg.GlobalCfg.CRISocket = "unix://" + kl.GetCRISocket("")
				}
			} else {
				// CRI socket supplied by user, check for existence
				criSocketPath := strings.TrimPrefix(cfg.GlobalCfg.CRISocket, "unix://")
				_, err := os.Stat(criSocketPath)
				if err != nil {
					enableContainerPolicy = false
					dm.Logger.Warnf("Error while looking for CRI socket file %s", err.Error())
				}
			}
		}

		if enableContainerPolicy {
			dm.SetContainerNSVisibility()

			// monitor containers
			if strings.Contains(cfg.GlobalCfg.CRISocket, "docker") {
				// update already deployed containers
				dm.GetAlreadyDeployedDockerContainers()
				// monitor docker events
				go dm.MonitorDockerEvents()
			} else if strings.Contains(cfg.GlobalCfg.CRISocket, "containerd") {
				// insuring NRI monitoring only in case containerd is present
				if cfg.GlobalCfg.NRIEnabled && dm.checkNRIAvailability() == nil {
					// monitor NRI events
					go dm.MonitorNRIEvents()
				} else {
					// monitor containerd events
					go dm.MonitorContainerdEvents()
				}
			} else if strings.Contains(cfg.GlobalCfg.CRISocket, "cri-o") {
				// monitor crio events
				go dm.MonitorCrioEvents()
			} else if cfg.GlobalCfg.UseOCIHooks {
				go dm.ListenToNonK8sHook()
			} else {
				enableContainerPolicy = false
				dm.Logger.Warnf("Failed to monitor containers: %s is not a supported CRI socket.", cfg.GlobalCfg.CRISocket)
			}

			if cfg.GlobalCfg.UseOCIHooks {
				dm.Logger.Printf("Using OCI Hooks for monitoring containers")
			} else {
				dm.Logger.Printf("Using %s for monitoring containers", cfg.GlobalCfg.CRISocket)
			}
		}
	}

	if dm.K8sEnabled && cfg.GlobalCfg.Policy {

		if cfg.GlobalCfg.UseOCIHooks &&
			(strings.Contains(dm.Node.ContainerRuntimeVersion, "cri-o") ||
				(strings.Contains(dm.Node.ContainerRuntimeVersion, "containerd") && dm.checkNRIAvailability() == nil)) {
			go dm.ListenToK8sHook()
		} else if dm.checkNRIAvailability() == nil {
			// monitor NRI events
			go dm.MonitorNRIEvents()
		} else if cfg.GlobalCfg.CRISocket != "" { // check if the CRI socket set while executing kubearmor exists
			trimmedSocket := strings.TrimPrefix(cfg.GlobalCfg.CRISocket, "unix://")
			if _, err := os.Stat(trimmedSocket); err != nil {
				dm.Logger.Warnf("Error while looking for CRI socket file: %s", err.Error())

				// destroy the daemon
				dm.DestroyKubeArmorDaemon()
				return
			}

			// monitor containers
			if strings.Contains(dm.Node.ContainerRuntimeVersion, "docker") || strings.Contains(cfg.GlobalCfg.CRISocket, "docker") {
				// update already deployed containers
				dm.GetAlreadyDeployedDockerContainers()
				// monitor docker events
				go dm.MonitorDockerEvents()
			} else if strings.Contains(dm.Node.ContainerRuntimeVersion, "containerd") || strings.Contains(cfg.GlobalCfg.CRISocket, "containerd") {
				// monitor containerd events
				go dm.MonitorContainerdEvents()
			} else if strings.Contains(dm.Node.ContainerRuntimeVersion, "cri-o") || strings.Contains(cfg.GlobalCfg.CRISocket, "cri-o") {
				// monitor crio events
				go dm.MonitorCrioEvents()
			} else {
				dm.Logger.Errf("Failed to monitor containers: %s is not a supported CRI socket.", cfg.GlobalCfg.CRISocket)
				// destroy the daemon
				dm.DestroyKubeArmorDaemon()
				return
			}

			dm.Logger.Printf("Using %s for monitoring containers", cfg.GlobalCfg.CRISocket)

		} else { // CRI socket not set, we'll have to auto detect
			dm.Logger.Print("CRI socket not set. Trying to detect.")

			if strings.HasPrefix(dm.Node.ContainerRuntimeVersion, "docker") {
				socketFile := kl.GetCRISocket("docker")

				if socketFile != "" {
					cfg.GlobalCfg.CRISocket = "unix://" + socketFile

					// update already deployed containers
					dm.GetAlreadyDeployedDockerContainers()

					// monitor docker events
					go dm.MonitorDockerEvents()
				} else {
					// we might have to use containerd's socket as docker's socket is not
					// available
					socketFile := kl.GetCRISocket("containerd")

					if socketFile != "" {
						cfg.GlobalCfg.CRISocket = "unix://" + socketFile

						// monitor containerd events
						go dm.MonitorContainerdEvents()
					} else {
						dm.Logger.Err("Failed to monitor containers (Docker socket file is not accessible)")

						// destroy the daemon
						dm.DestroyKubeArmorDaemon()

						return
					}
				}
			} else if strings.HasPrefix(dm.Node.ContainerRuntimeVersion, "containerd") { // containerd
				socketFile := kl.GetCRISocket("containerd")

				if socketFile != "" {
					cfg.GlobalCfg.CRISocket = "unix://" + socketFile

					// monitor containerd events
					go dm.MonitorContainerdEvents()
				} else {
					dm.Logger.Err("Failed to monitor containers (Containerd socket file is not accessible)")

					// destroy the daemon
					dm.DestroyKubeArmorDaemon()

					return
				}
			} else if strings.HasPrefix(dm.Node.ContainerRuntimeVersion, "cri-o") { // cri-o
				socketFile := kl.GetCRISocket("cri-o")

				if socketFile != "" {
					cfg.GlobalCfg.CRISocket = "unix://" + socketFile

					// monitor cri-o events
					go dm.MonitorCrioEvents()
				} else {
					dm.Logger.Err("Failed to monitor containers (CRI-O socket file is not accessible)")

					// destroy the daemon
					dm.DestroyKubeArmorDaemon()

					return
				}
			}
		}
	}

	// == //

	// wait for a while
	time.Sleep(time.Second * 1)

	// == //

	// Init USB Device Handler
	if cfg.GlobalCfg.HostPolicy && cfg.GlobalCfg.USBDeviceHandler {
		if !dm.InitUSBDeviceHandler() {
			dm.Logger.Warn("Failed to initialize KubeArmor USB Device Handler")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Initialized KubeArmor USB Device Handler")
	}

	// == //

	timeout, err := time.ParseDuration(cfg.GlobalCfg.InitTimeout)
	if dm.K8sEnabled && cfg.GlobalCfg.Policy {
		if err != nil {
			dm.Logger.Warnf("Not a valid InitTimeout duration: %q, defaulting to '60s'", cfg.GlobalCfg.InitTimeout)
			timeout = 60 * time.Second
		}

		// watch security policies
		securityPoliciesSynced := dm.WatchSecurityPolicies()
		if securityPoliciesSynced == nil {
			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Started to monitor security policies")

		// watch cluster security policies
		clusterSecurityPoliciesSynced := dm.WatchClusterSecurityPolicies(timeout)
		if clusterSecurityPoliciesSynced == nil {
			dm.Logger.Warn("error while monitoring cluster security policies, informer cache not synced")
		} else {
			dm.Logger.Print("Started to monitor cluster security policies")
		}

		// watch default posture
		defaultPostureSynced := dm.WatchDefaultPosture()
		if defaultPostureSynced == nil {
			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Started to monitor per-namespace default posture")

		// watch kubearmor configmap
		configMapSynced := dm.WatchConfigMap()
		if configMapSynced == nil {
			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}
		dm.Logger.Print("Watching for posture changes")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		synced := cache.WaitForCacheSync(ctx.Done(), securityPoliciesSynced, defaultPostureSynced, configMapSynced)
		if !synced {
			dm.Logger.Err("Failed to sync Kubernetes informers")

			// destroy the daemon
			dm.DestroyKubeArmorDaemon()

			return
		}

		// watch k8s pods (function never returns, must be called in a
		// goroutine)
		go dm.WatchK8sPods()
		dm.Logger.Print("Started to monitor Pod events")
	}

	if dm.K8sEnabled && cfg.GlobalCfg.HostPolicy {
		// watch host security policies
		go dm.WatchHostSecurityPolicies(timeout)
	}

	if !dm.K8sEnabled && (enableContainerPolicy || cfg.GlobalCfg.HostPolicy) {
		policyService := &policy.PolicyServer{
			ContainerPolicyEnabled: enableContainerPolicy,
			HostPolicyEnabled:      cfg.GlobalCfg.HostPolicy,
		}
		if enableContainerPolicy {
			policyService.UpdateContainerPolicy = dm.ParseAndUpdateContainerSecurityPolicy
			dm.Logger.Print("Started to monitor container security policies on gRPC")
		}
		if cfg.GlobalCfg.HostPolicy {
			policyService.UpdateHostPolicy = dm.ParseAndUpdateHostSecurityPolicy
			dm.Node.PolicyEnabled = tp.KubeArmorPolicyEnabled
			dm.Logger.Print("Started to monitor host security policies on gRPC")
		}
		pb.RegisterPolicyServiceServer(dm.Logger.LogServer, policyService)

		//Enable grpc service to send kubearmor data to client in unorchestrated mode
		probe := &Probe{}
		probe.GetContainerData = dm.SetProbeContainerData
		pb.RegisterProbeServiceServer(dm.Logger.LogServer, probe)

		if err := dm.SetHealthStatus(pb.PolicyService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
			dm.Logger.Warnf("Failed to set health status for PolicyService: %v", err)
		}
		if err := dm.SetHealthStatus(pb.ProbeService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
			dm.Logger.Warnf("Failed to set health status for ProbeService: %v", err)
		}
	}

	reflection.Register(dm.Logger.LogServer) // Helps grpc clients list out what all svc/endpoints available

	// serve log feeds
	go dm.ServeLogFeeds()
	dm.Logger.Print("Started to serve gRPC-based log feeds")
	if err := dm.SetHealthStatus(pb.LogService_ServiceDesc.ServiceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
		dm.Logger.Warnf("Failed to set health status for LogService: %v", err)
	}

	// == //
	go dm.SetKarmorData()
	dm.Logger.Print("Initialized KubeArmor")
	// == //

	if cfg.GlobalCfg.KVMAgent || !dm.K8sEnabled {
		// Restore and apply all kubearmor host security policies
		dm.restoreKubeArmorPolicies()
	}
	// == //

	// Init KvmAgent
	if cfg.GlobalCfg.KVMAgent {
		// initialize kvm agent
		if err := dm.InitKVMAgent(); err != nil {
			dm.Logger.Errf("Failed to initialize KVM Agent: %s", err.Error())

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
	}

	// destroy the daemon
	dm.DestroyKubeArmorDaemon()
}

func (dm *KubeArmorDaemon) checkNRIAvailability() error {
	// Check if nri socket is set, if not then auto detect
	if cfg.GlobalCfg.NRISocket == "" {
		if kl.GetNRISocket("") != "" {
			cfg.GlobalCfg.NRISocket = kl.GetNRISocket("")
		} else {
			return fmt.Errorf("NRI socket file not found")
		}
	} else {
		// NRI socket supplied by user, check for existence
		_, err := os.Stat(cfg.GlobalCfg.NRISocket)
		if err != nil {
			return fmt.Errorf("NRI socket file not found: %w", err)
		}
	}
	return nil
}
