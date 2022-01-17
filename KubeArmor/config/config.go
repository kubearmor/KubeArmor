// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package config

import (
	"os"

	"flag"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
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

	KVMAgent bool // Enable/Disable KVM Agent
}

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

func readCmdLineParams() {
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	hostStr := flag.String(ConfigHost, kl.GetHostName(), "host name")

	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")
	logStr := flag.String(ConfigLogPath, "/tmp/kubearmor.log", "log file path, {path|stdout|none}")
	seLinuxProfileDirStr := flag.String(ConfigSELinuxProfileDir, "/tmp/kubearmor.selinux", "SELinux profile directory")

	visStr := flag.String(ConfigVisibility, "process,file,network,capabilities", "Container Visibility to use [process,file,network,capabilities,none]")
	hostVisStr := flag.String(ConfigHostVisibility, "process,file,network,capabilities", "Host Visibility to use [process,file,network,capabilities,none]")

	policyB := flag.Bool(ConfigKubearmorPolicy, true, "enabling KubeArmorPolicy")
	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")

	kvmAgentB := flag.Bool(ConfigKubearmorVM, false, "enabling KubeArmorVM")

	flag.Parse()

	viper.Set(ConfigCluster, *clusterStr)
	viper.Set(ConfigHost, *hostStr)

	viper.Set(ConfigGRPC, *grpcStr)
	viper.Set(ConfigLogPath, *logStr)
	viper.Set(ConfigSELinuxProfileDir, *seLinuxProfileDirStr)

	viper.Set(ConfigVisibility, *visStr)
	viper.Set(ConfigHostVisibility, *hostVisStr)

	viper.Set(ConfigKubearmorPolicy, *policyB)
	viper.Set(ConfigKubearmorHostPolicy, *hostPolicyB)

	viper.Set(ConfigKubearmorVM, *kvmAgentB)
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
		GlobalCfg.HostPolicy = true
	}

	kg.Printf("config [%+v]", GlobalCfg)

	return nil
}
