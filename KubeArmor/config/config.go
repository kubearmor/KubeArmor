// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package config

import (
	"os"

	"flag"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/spf13/viper"
)

// KubearmorConfig Configuration structure for Kubearmor
type KubearmorConfig struct {
	Grpc           string // GRPC Port to use
	Cluster        string // Cluster name to use for feeds
	LogPath        string // Log file to use
	HostVisibility string // Host visibility to use for kubearmor in process mode
	Policy         bool   // Enable/Disable policy enforcement
	HostPolicy     bool   // Enable/Disable host policy enforcement
	KVMAgent       bool   // Enable/Disable KVM Agent
}

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KubearmorConfig

// ConfigCluster Cluster name key
const ConfigCluster string = "cluster"

// ConfigGRPC GRPC Port key
const ConfigGRPC string = "gRPC"

// ConfigLogPath Log Path key
const ConfigLogPath string = "logPath"

// ConfigHostVisibility Host visibility key
const ConfigHostVisibility string = "hostVisibility"

// ConfigKubearmorPolicy Kubearmor policy key
const ConfigKubearmorPolicy string = "enableKubeArmorPolicy"

// ConfigKubearmorHostPolicy Kubearmor host policy key
const ConfigKubearmorHostPolicy string = "enableKubeArmorHostPolicy"

// ConfigKubearmorVM Kubearmor VM key
const ConfigKubearmorVM string = "enableKubeArmorVm"

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func readCmdLineParams() {
	// Read configuration from command line
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")
	logStr := flag.String(ConfigLogPath, "/tmp/kubearmor.log", "log file path, {path|stdout|none}")
	policyB := flag.Bool(ConfigKubearmorPolicy, true, "enabling KubeArmorPolicy")
	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")
	kvmAgentB := flag.Bool(ConfigKubearmorVM, false, "enabling KubeArmorVM")
	hostVisStr := flag.String(ConfigHostVisibility, "process,file,network,capabilities", "Host Visibility to use [process,file,network,capabilities,none]")

	flag.Parse()
	viper.Set(ConfigCluster, *clusterStr)
	viper.Set(ConfigGRPC, *grpcStr)
	viper.Set(ConfigLogPath, *logStr)
	viper.Set(ConfigHostVisibility, *hostVisStr)
	viper.Set(ConfigKubearmorPolicy, *policyB)
	viper.Set(ConfigKubearmorHostPolicy, *hostPolicyB)
	viper.Set(ConfigKubearmorVM, *kvmAgentB)
}

// LoadConfig Load configuration
func LoadConfig() error {
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

	GlobalCfg.Grpc = viper.GetString(ConfigGRPC)
	GlobalCfg.Cluster = viper.GetString(ConfigCluster)
	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)
	GlobalCfg.Policy = viper.GetBool(ConfigKubearmorPolicy)
	GlobalCfg.HostPolicy = viper.GetBool(ConfigKubearmorHostPolicy)
	GlobalCfg.KVMAgent = viper.GetBool(ConfigKubearmorVM)
	GlobalCfg.HostVisibility = viper.GetString(ConfigHostVisibility)

	if GlobalCfg.KVMAgent {
		GlobalCfg.HostPolicy = true
	}

	kg.Printf("config [%+v]", GlobalCfg)
	return nil
}
