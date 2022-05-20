// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package config

import (
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

	Visibility     string // Container visibility to use
	HostVisibility string // Host visibility to use

	Policy     bool // Enable/Disable policy enforcement
	HostPolicy bool // Enable/Disable host policy enforcement
	KVMAgent   bool // Enable/Disable KVM Agent
	K8sEnv     bool // Is k8s env ?

	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	DefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context

	CoverageTest bool // Enable/Disable Coverage Test
}

// PolicyDir policy dir path for host policies backup
const PolicyDir string = "/opt/kubearmor/policies/"

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KubearmorConfig

// ConfigCluster Cluster name key
const ConfigCluster string = "cluster"

// ConfigHost Host name key
const ConfigHost string = "localhost"

// ConfigGRPC GRPC Port key
const ConfigGRPC string = "gRPC"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

// ConfigSELinuxProfileDir SELinux Profile Directory key
const ConfigSELinuxProfileDir string = "seLinuxProfileDir"

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

// ConfigCoverageTest Coverage Test key
const ConfigCoverageTest string = "coverageTest"

// ConfigK8sEnv VM key
const ConfigK8sEnv string = "k8s"

func readCmdLineParams() {
	hostname, _ := os.Hostname()
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	hostStr := flag.String(ConfigHost, strings.Split(hostname, ".")[0], "host name")

	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")
	logStr := flag.String(ConfigLogPath, "/tmp/kubearmor.log", "log file path, {path|stdout|none}")
	seLinuxProfileDirStr := flag.String(ConfigSELinuxProfileDir, "/tmp/kubearmor.selinux", "SELinux profile directory")

	visStr := flag.String(ConfigVisibility, "process,file,network,capabilities", "Container Visibility to use [process,file,network,capabilities,none]")
	hostVisStr := flag.String(ConfigHostVisibility, "", "Host Visibility to use [process,file,network,capabilities,none] (default \"none\" for k8s, \"process,file,network,capabilities\" for VM)")

	policyB := flag.Bool(ConfigKubearmorPolicy, true, "enabling KubeArmorPolicy")
	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")
	kvmAgentB := flag.Bool(ConfigKubearmorVM, false, "enabling KubeArmorVM")
	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is k8s env?")

	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "block", "configuring default enforcement action in global file context [audit,block]")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "block", "configuring default enforcement action in global network context [audit,block]")
	defaultCapabilitiesPosture := flag.String(ConfigDefaultCapabilitiesPosture, "block", "configuring default enforcement action in global capability context [audit,block]")

	coverageTestB := flag.Bool(ConfigCoverageTest, false, "enabling CoverageTest")

	flag.Parse()

	viper.SetDefault(ConfigCluster, *clusterStr)
	viper.SetDefault(ConfigHost, *hostStr)

	viper.SetDefault(ConfigGRPC, *grpcStr)
	viper.SetDefault(ConfigLogPath, *logStr)
	viper.SetDefault(ConfigSELinuxProfileDir, *seLinuxProfileDirStr)

	viper.SetDefault(ConfigVisibility, *visStr)
	viper.SetDefault(ConfigHostVisibility, *hostVisStr)

	viper.SetDefault(ConfigKubearmorPolicy, *policyB)
	viper.SetDefault(ConfigKubearmorHostPolicy, *hostPolicyB)
	viper.SetDefault(ConfigKubearmorVM, *kvmAgentB)
	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)
	viper.SetDefault(ConfigDefaultCapabilitiesPosture, *defaultCapabilitiesPosture)

	viper.SetDefault(ConfigCoverageTest, *coverageTestB)
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

	GlobalCfg.Visibility = viper.GetString(ConfigVisibility)
	GlobalCfg.HostVisibility = viper.GetString(ConfigHostVisibility)

	GlobalCfg.Policy = viper.GetBool(ConfigKubearmorPolicy)
	GlobalCfg.HostPolicy = viper.GetBool(ConfigKubearmorHostPolicy)
	GlobalCfg.KVMAgent = viper.GetBool(ConfigKubearmorVM)
	if GlobalCfg.KVMAgent {
		GlobalCfg.Policy = false
		GlobalCfg.HostPolicy = true
	}
	GlobalCfg.K8sEnv = viper.GetBool(ConfigK8sEnv)

	GlobalCfg.DefaultFilePosture = viper.GetString(ConfigDefaultFilePosture)
	GlobalCfg.DefaultNetworkPosture = viper.GetString(ConfigDefaultNetworkPosture)
	GlobalCfg.DefaultCapabilitiesPosture = viper.GetString(ConfigDefaultCapabilitiesPosture)

	if GlobalCfg.HostVisibility == "" {
		if GlobalCfg.KVMAgent || (!GlobalCfg.K8sEnv && GlobalCfg.HostPolicy) {
			GlobalCfg.HostVisibility = "process,file,network,capabilities"
		} else { // k8s
			GlobalCfg.HostVisibility = "none"
		}
	}

	GlobalCfg.CoverageTest = viper.GetBool(ConfigCoverageTest)

	kg.Printf("config [%+v]", GlobalCfg)

	return nil
}
