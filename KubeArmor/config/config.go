// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package config is the component responsible for loading KubeArmor configurations
package config

import (
	"fmt"
	"os"
	"strings"

	"flag"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

// KubearmorConfig Structure
type KubearmorConfig struct {
	Cluster string // Cluster name to use for feeds
	Host    string // Host name to use for feeds

	GRPC              string // gRPC Port to use
	LogPath           string // Log file to use
	SELinuxProfileDir string // Directory to store SELinux profiles
	CRISocket         string // Container runtime to use

	Visibility     string // Container visibility to use
	HostVisibility string // Host visibility to use

	Policy     bool // Enable/Disable policy enforcement
	HostPolicy bool // Enable/Disable host policy enforcement
	KVMAgent   bool // Enable/Disable KVM Agent
	K8sEnv     bool // Is k8s env ?

	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	DefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context

	HostDefaultFilePosture         string // Default Enforcement Action in Global File Context
	HostDefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	HostDefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context

	CoverageTest bool // Enable/Disable Coverage Test

	LsmOrder  []string // LSM order
	BPFFsPath string   // path to the BPF filesystem
}

// PolicyDir policy dir path for host policies backup
const PolicyDir string = "/opt/kubearmor/policies/"

// PIDFilePath for pid file path
const PIDFilePath string = "/opt/kubearmor/kubearmor.pid"

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KubearmorConfig

// ConfigCluster Cluster name key
const ConfigCluster string = "cluster"

// ConfigHost Host name key
const ConfigHost string = "host"

// ConfigGRPC GRPC Port key
const ConfigGRPC string = "gRPC"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

// ConfigSELinuxProfileDir SELinux Profile Directory key
const ConfigSELinuxProfileDir string = "seLinuxProfileDir"

// ConfigCRISocket key
const ConfigCRISocket string = "criSocket"

// ConfigVisibility Container visibility key
const ConfigVisibility string = "visibility"

// ConfigHostVisibility Host visibility key
const ConfigHostVisibility string = "hostVisibility"

// ConfigKubearmorPolicy Kubearmor policy key
const ConfigKubearmorPolicy string = "enableKubeArmorPolicy"

// ConfigKubearmorHostPolicy Kubearmor host policy key
const ConfigKubearmorHostPolicy string = "enableKubeArmorHostPolicy"

// ConfigKubearmorVM Kubearmor VM key
const ConfigKubearmorVM string = "enableKubeArmorVm"

// ConfigDefaultFilePosture KubeArmor Default Global File Posture key
const ConfigDefaultFilePosture string = "defaultFilePosture"

// ConfigDefaultNetworkPosture KubeArmor Default Global Network Posture key
const ConfigDefaultNetworkPosture string = "defaultNetworkPosture"

// ConfigDefaultCapabilitiesPosture KubeArmor Default Global Capabilities Posture key
const ConfigDefaultCapabilitiesPosture string = "defaultCapabilitiesPosture"

// ConfigHostDefaultFilePosture KubeArmor Default Global File Posture key
const ConfigHostDefaultFilePosture string = "hostDefaultFilePosture"

// ConfigHostDefaultNetworkPosture KubeArmor Default Global Network Posture key
const ConfigHostDefaultNetworkPosture string = "hostDefaultNetworkPosture"

// ConfigHostDefaultCapabilitiesPosture KubeArmor Default Global Capabilities Posture key
const ConfigHostDefaultCapabilitiesPosture string = "hostDefaultCapabilitiesPosture"

// ConfigCoverageTest Coverage Test key
const ConfigCoverageTest string = "coverageTest"

// ConfigK8sEnv VM key
const ConfigK8sEnv string = "k8s"

// LsmOrder Preference order of the LSMs
const LsmOrder string = "lsm"

// BPFFsPath key
const BPFFsPath string = "bpfFsPath"

func readCmdLineParams() {
	hostname, _ := os.Hostname()
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	hostStr := flag.String(ConfigHost, strings.Split(hostname, ".")[0], "host name")

	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")
	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")
	seLinuxProfileDirStr := flag.String(ConfigSELinuxProfileDir, "/tmp/kubearmor.selinux", "SELinux profile directory")
	criSocket := flag.String(ConfigCRISocket, "", "path to CRI socket (format: unix:///path/to/file.sock)")

	visStr := flag.String(ConfigVisibility, "process,file,network,capabilities", "Container Visibility to use [process,file,network,capabilities,none]")
	hostVisStr := flag.String(ConfigHostVisibility, "default", "Host Visibility to use [process,file,network,capabilities,none] (default \"none\" for k8s, \"process,file,network,capabilities\" for VM)")

	policyB := flag.Bool(ConfigKubearmorPolicy, true, "enabling KubeArmorPolicy")
	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")
	kvmAgentB := flag.Bool(ConfigKubearmorVM, false, "enabling KubeArmorVM")
	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is k8s env?")

	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "audit", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "audit", "configuring default enforcement action in global network context {allow|audit|block}")
	defaultCapabilitiesPosture := flag.String(ConfigDefaultCapabilitiesPosture, "audit", "configuring default enforcement action in global capability context {allow|audit|block}")

	hostDefaultFilePosture := flag.String(ConfigHostDefaultFilePosture, "audit", "configuring default enforcement action in global file context {allow|audit|block}")
	hostDefaultNetworkPosture := flag.String(ConfigHostDefaultNetworkPosture, "audit", "configuring default enforcement action in global network context {allow|audit|block}")
	hostDefaultCapabilitiesPosture := flag.String(ConfigHostDefaultCapabilitiesPosture, "audit", "configuring default enforcement action in global capability context {allow|audit|block}")

	coverageTestB := flag.Bool(ConfigCoverageTest, false, "enabling CoverageTest")

	lsmOrder := flag.String(LsmOrder, "bpf,apparmor,selinux", "lsm preference order to use, available lsms [bpf, apparmor, selinux]")

	bpfFsPath := flag.String(BPFFsPath, "/sys/fs/bpf", "Path to the BPF filesystem to use for storing maps")

	flags := []string{}
	flag.VisitAll(func(f *flag.Flag) {
		kv := fmt.Sprintf("%s:%v", f.Name, f.Value)
		flags = append(flags, kv)
	})
	kg.Printf("Arguments [%s]", strings.Join(flags, " "))

	flag.Parse()

	viper.SetDefault(ConfigCluster, *clusterStr)
	viper.SetDefault(ConfigHost, *hostStr)

	viper.SetDefault(ConfigGRPC, *grpcStr)
	viper.SetDefault(ConfigLogPath, *logStr)
	viper.SetDefault(ConfigSELinuxProfileDir, *seLinuxProfileDirStr)
	viper.SetDefault(ConfigCRISocket, *criSocket)

	viper.SetDefault(ConfigVisibility, *visStr)
	viper.SetDefault(ConfigHostVisibility, *hostVisStr)

	viper.SetDefault(ConfigKubearmorPolicy, *policyB)
	viper.SetDefault(ConfigKubearmorHostPolicy, *hostPolicyB)
	viper.SetDefault(ConfigKubearmorVM, *kvmAgentB)
	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)
	viper.SetDefault(ConfigDefaultCapabilitiesPosture, *defaultCapabilitiesPosture)

	viper.SetDefault(ConfigHostDefaultFilePosture, *hostDefaultFilePosture)
	viper.SetDefault(ConfigHostDefaultNetworkPosture, *hostDefaultNetworkPosture)
	viper.SetDefault(ConfigHostDefaultCapabilitiesPosture, *hostDefaultCapabilitiesPosture)

	viper.SetDefault(ConfigCoverageTest, *coverageTestB)

	viper.SetDefault(LsmOrder, *lsmOrder)

	viper.SetDefault(BPFFsPath, *bpfFsPath)
}

// LoadConfig Load configuration
func LoadConfig() error {
	// Read configuration from command line
	readCmdLineParams()

	// Read configuration from env var
	// Note that the env var has to be set in uppercase for e.g, CLUSTER=xyz ./kubearmor
	viper.AutomaticEnv()

	// Read configuration from config file
	cfgfile := os.Getenv("KUBEARMOR_CFG")
	if cfgfile == "" {
		cfgfile = "kubearmor.yaml"
	}
	if _, err := os.Stat(cfgfile); err == nil {
		kg.Printf("setting config from file [%s]", cfgfile)
		viper.SetConfigFile(cfgfile)
		err := viper.ReadInConfig()
		if err != nil {
			return err
		}
	}

	GlobalCfg.Cluster = viper.GetString(ConfigCluster)
	GlobalCfg.Host = viper.GetString(ConfigHost)

	GlobalCfg.GRPC = viper.GetString(ConfigGRPC)
	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)
	GlobalCfg.SELinuxProfileDir = viper.GetString(ConfigSELinuxProfileDir)

	GlobalCfg.CRISocket = os.Getenv("CRI_SOCKET")
	if GlobalCfg.CRISocket == "" {
		GlobalCfg.CRISocket = viper.GetString(ConfigCRISocket)
	}

	if GlobalCfg.CRISocket != "" && !strings.HasPrefix(GlobalCfg.CRISocket, "unix://") {
		return fmt.Errorf("CRI socket must start with 'unix://' (%s is invalid)", GlobalCfg.CRISocket)
	}

	GlobalCfg.Visibility = viper.GetString(ConfigVisibility)
	GlobalCfg.HostVisibility = viper.GetString(ConfigHostVisibility)

	GlobalCfg.Policy = viper.GetBool(ConfigKubearmorPolicy)
	GlobalCfg.HostPolicy = viper.GetBool(ConfigKubearmorHostPolicy)
	GlobalCfg.KVMAgent = viper.GetBool(ConfigKubearmorVM)
	GlobalCfg.K8sEnv = viper.GetBool(ConfigK8sEnv)

	GlobalCfg.DefaultFilePosture = viper.GetString(ConfigDefaultFilePosture)
	GlobalCfg.DefaultNetworkPosture = viper.GetString(ConfigDefaultNetworkPosture)
	GlobalCfg.DefaultCapabilitiesPosture = viper.GetString(ConfigDefaultCapabilitiesPosture)

	GlobalCfg.HostDefaultFilePosture = viper.GetString(ConfigHostDefaultFilePosture)
	GlobalCfg.HostDefaultNetworkPosture = viper.GetString(ConfigHostDefaultNetworkPosture)
	GlobalCfg.HostDefaultCapabilitiesPosture = viper.GetString(ConfigHostDefaultCapabilitiesPosture)

	kg.Printf("Configuration [%+v]", GlobalCfg)

	if GlobalCfg.KVMAgent {
		GlobalCfg.Policy = false
		GlobalCfg.HostPolicy = true
	}

	if GlobalCfg.HostVisibility == "default" {
		if GlobalCfg.KVMAgent || (!GlobalCfg.K8sEnv && GlobalCfg.HostPolicy) {
			GlobalCfg.HostVisibility = "process,file,network,capabilities"
		} else { // k8s
			GlobalCfg.HostVisibility = "none"
		}
	}

	GlobalCfg.CoverageTest = viper.GetBool(ConfigCoverageTest)

	GlobalCfg.LsmOrder = strings.Split(viper.GetString(LsmOrder), ",")

	GlobalCfg.BPFFsPath = viper.GetString(BPFFsPath)

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
