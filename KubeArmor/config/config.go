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
	TLSEnabled        bool   // enable tls
	TLSCertPath       string // tls certification path
	TLSCertProvider   string // tls certficate provider
	LogPath           string // Log file to use
	SELinuxProfileDir string // Directory to store SELinux profiles
	CRISocket         string // Container runtime to use
	NRISocket         string // NRI socket to use
	NRIIndex          string // NRI socket to use

	Visibility     string // Container visibility to use
	HostVisibility string // Host visibility to use

	Policy     bool // Enable/Disable policy enforcement
	HostPolicy bool // Enable/Disable host policy enforcement
	KVMAgent   bool // Enable/Disable KVM Agent
	K8sEnv     bool // Is k8s env ?

	Debug bool // Enable/Disable KubeArmor debug mode

	DefaultFilePosture         string // Default Enforcement Action in Global File Context
	DefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	DefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context

	HostDefaultFilePosture         string // Default Enforcement Action in Global File Context
	HostDefaultNetworkPosture      string // Default Enforcement Action in Global Network Context
	HostDefaultCapabilitiesPosture string // Default Enforcement Action in Global Capabilities Context

	CoverageTest       bool     // Enable/Disable Coverage Test
	ConfigUntrackedNs  []string // untracked namespaces
	LsmOrder           []string // LSM order
	BPFFsPath          string   // path to the BPF filesystem
	EnforcerAlerts     bool     // policy enforcer
	DefaultPostureLogs bool     // Enable/Disable Default Posture logs for AppArmor LSM
	InitTimeout        string   // Timeout for main thread init stages

	StateAgent bool // enable KubeArmor state agent
}

// GlobalCfg Global configuration for Kubearmor
var GlobalCfg KubearmorConfig

// Config const
const (
	PolicyDir                            string = "/opt/kubearmor/policies/"
	PIDFilePath                          string = "/opt/kubearmor/kubearmor.pid"
	ConfigCluster                        string = "cluster"
	ConfigHost                           string = "host"
	ConfigGRPC                           string = "gRPC"
	ConfigTLSCertPath                    string = "tlsCertPath"
	ConfigTLSCertProvider                string = "tlsCertProvider"
	SelfCertProvider                     string = "self"
	ExternalCertProvider                 string = "external"
	ConfigTLS                            string = "tlsEnabled"
	ConfigLogPath                        string = "logPath"
	ConfigSELinuxProfileDir              string = "seLinuxProfileDir"
	ConfigCRISocket                      string = "criSocket"
	ConfigNRISocket                      string = "nriSocket"
	ConfigNRIIndex                       string = "nriIndex"
	ConfigVisibility                     string = "visibility"
	ConfigHostVisibility                 string = "hostVisibility"
	ConfigKubearmorPolicy                string = "enableKubeArmorPolicy"
	ConfigKubearmorHostPolicy            string = "enableKubeArmorHostPolicy"
	ConfigKubearmorVM                    string = "enableKubeArmorVm"
	ConfigDefaultFilePosture             string = "defaultFilePosture"
	ConfigDefaultNetworkPosture          string = "defaultNetworkPosture"
	ConfigDefaultCapabilitiesPosture     string = "defaultCapabilitiesPosture"
	ConfigHostDefaultFilePosture         string = "hostDefaultFilePosture"
	ConfigHostDefaultNetworkPosture      string = "hostDefaultNetworkPosture"
	ConfigHostDefaultCapabilitiesPosture string = "hostDefaultCapabilitiesPosture"
	ConfigCoverageTest                   string = "coverageTest"
	ConfigK8sEnv                         string = "k8s"
	ConfigDebug                          string = "debug"
	ConfigUntrackedNs                    string = "untrackedNs"
	LsmOrder                             string = "lsm"
	BPFFsPath                            string = "bpfFsPath"
	EnforcerAlerts                       string = "enforcerAlerts"
	ConfigDefaultPostureLogs             string = "defaultPostureLogs"
	ConfigInitTimeout                    string = "initTimeout"
	ConfigStateAgent                     string = "enableKubeArmorStateAgent"
)

func readCmdLineParams() {
	hostname, _ := os.Hostname()
	clusterStr := flag.String(ConfigCluster, "default", "cluster name")
	hostStr := flag.String(ConfigHost, hostname, "host name")

	grpcStr := flag.String(ConfigGRPC, "32767", "gRPC port number")
	tlsEnabled := flag.Bool(ConfigTLS, false, "enable tls for secure grpc connection")
	tlsCertsStr := flag.String(ConfigTLSCertPath, "/var/lib/kubearmor/tls", "path to tls ca certificate files ca.crt, ca.crt")
	tlsCertProvider := flag.String(ConfigTLSCertProvider, "self", "source of certificate {self|external}, self: create certificate dynamically, external: provided by some external entity")
	logStr := flag.String(ConfigLogPath, "none", "log file path, {path|stdout|none}")
	seLinuxProfileDirStr := flag.String(ConfigSELinuxProfileDir, "/tmp/kubearmor.selinux", "SELinux profile directory")
	criSocket := flag.String(ConfigCRISocket, "", "path to CRI socket (format: unix:///path/to/file.sock)")
	nriSocket := flag.String(ConfigNRISocket, "", "path to NRI socket (format: /path/to/file.sock)")
	nriIndex := flag.String(ConfigNRIIndex, "99", "NRI plugin index")

	visStr := flag.String(ConfigVisibility, "process,file,network,capabilities", "Container Visibility to use [process,file,network,capabilities,none]")
	hostVisStr := flag.String(ConfigHostVisibility, "default", "Host Visibility to use [process,file,network,capabilities,none] (default \"none\" for k8s, \"process,file,network,capabilities\" for VM)")

	policyB := flag.Bool(ConfigKubearmorPolicy, true, "enabling KubeArmorPolicy")
	hostPolicyB := flag.Bool(ConfigKubearmorHostPolicy, false, "enabling KubeArmorHostPolicy")
	kvmAgentB := flag.Bool(ConfigKubearmorVM, false, "enabling KubeArmorVM")
	k8sEnvB := flag.Bool(ConfigK8sEnv, true, "is k8s env?")

	debugB := flag.Bool(ConfigDebug, false, "Enable/Disable pushing KubeArmor debug logs over gRPC. NOTE: Set environment DEBUG=true to configure stdout debug logging")

	defaultFilePosture := flag.String(ConfigDefaultFilePosture, "audit", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosture := flag.String(ConfigDefaultNetworkPosture, "audit", "configuring default enforcement action in global network context {allow|audit|block}")
	defaultCapabilitiesPosture := flag.String(ConfigDefaultCapabilitiesPosture, "audit", "configuring default enforcement action in global capability context {allow|audit|block}")

	hostDefaultFilePosture := flag.String(ConfigHostDefaultFilePosture, "audit", "configuring default enforcement action in global file context {allow|audit|block}")
	hostDefaultNetworkPosture := flag.String(ConfigHostDefaultNetworkPosture, "audit", "configuring default enforcement action in global network context {allow|audit|block}")
	hostDefaultCapabilitiesPosture := flag.String(ConfigHostDefaultCapabilitiesPosture, "audit", "configuring default enforcement action in global capability context {allow|audit|block}")

	coverageTestB := flag.Bool(ConfigCoverageTest, false, "enabling CoverageTest")

	untrackedNs := flag.String(ConfigUntrackedNs, "kube-system,kubearmor", "Namespaces which are not being tracked, default untracked:[kube-system, kubearmor]")

	lsmOrder := flag.String(LsmOrder, "bpf,apparmor,selinux", "lsm preference order to use, available lsms [bpf, apparmor, selinux]")

	bpfFsPath := flag.String(BPFFsPath, "/sys/fs/bpf", "Path to the BPF filesystem to use for storing maps")
	enforcerAlerts := flag.Bool(EnforcerAlerts, true, "ebpf alerts")

	defaultPostureLogs := flag.Bool(ConfigDefaultPostureLogs, true, "Default Posture Alerts (for Apparmor only)")

	initTimeout := flag.String(ConfigInitTimeout, "60s", "Timeout for main thread init stages")

	stateAgent := flag.Bool(ConfigStateAgent, false, "enabling KubeArmor State Agent client")

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
	viper.SetDefault(ConfigTLS, *tlsEnabled)
	viper.SetDefault(ConfigTLSCertPath, *tlsCertsStr)
	viper.SetDefault(ConfigTLSCertProvider, *tlsCertProvider)
	viper.SetDefault(ConfigLogPath, *logStr)
	viper.SetDefault(ConfigSELinuxProfileDir, *seLinuxProfileDirStr)
	viper.SetDefault(ConfigCRISocket, *criSocket)
	viper.SetDefault(ConfigNRISocket, *nriSocket)
	viper.SetDefault(ConfigNRIIndex, *nriIndex)

	viper.SetDefault(ConfigVisibility, *visStr)
	viper.SetDefault(ConfigHostVisibility, *hostVisStr)

	viper.SetDefault(ConfigKubearmorPolicy, *policyB)
	viper.SetDefault(ConfigKubearmorHostPolicy, *hostPolicyB)
	viper.SetDefault(ConfigKubearmorVM, *kvmAgentB)
	viper.SetDefault(ConfigK8sEnv, *k8sEnvB)

	viper.SetDefault(ConfigDebug, *debugB)

	viper.SetDefault(ConfigDefaultFilePosture, *defaultFilePosture)
	viper.SetDefault(ConfigDefaultNetworkPosture, *defaultNetworkPosture)
	viper.SetDefault(ConfigDefaultCapabilitiesPosture, *defaultCapabilitiesPosture)

	viper.SetDefault(ConfigHostDefaultFilePosture, *hostDefaultFilePosture)
	viper.SetDefault(ConfigHostDefaultNetworkPosture, *hostDefaultNetworkPosture)
	viper.SetDefault(ConfigHostDefaultCapabilitiesPosture, *hostDefaultCapabilitiesPosture)

	viper.SetDefault(ConfigCoverageTest, *coverageTestB)

	viper.SetDefault(ConfigUntrackedNs, *untrackedNs)

	viper.SetDefault(LsmOrder, *lsmOrder)

	viper.SetDefault(BPFFsPath, *bpfFsPath)

	viper.SetDefault(EnforcerAlerts, *enforcerAlerts)

	viper.SetDefault(ConfigDefaultPostureLogs, *defaultPostureLogs)

	viper.SetDefault(ConfigInitTimeout, *initTimeout)

	viper.SetDefault(ConfigStateAgent, *stateAgent)
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
	if hostname, err := os.Hostname(); GlobalCfg.Host == "" && err == nil {
		GlobalCfg.Host = strings.Split(hostname, ".")[0]
	}

	GlobalCfg.GRPC = viper.GetString(ConfigGRPC)
	GlobalCfg.TLSEnabled = viper.GetBool(ConfigTLS)
	GlobalCfg.TLSCertPath = viper.GetString(ConfigTLSCertPath)
	GlobalCfg.TLSCertProvider = viper.GetString(ConfigTLSCertProvider)
	GlobalCfg.LogPath = viper.GetString(ConfigLogPath)

	GlobalCfg.CRISocket = os.Getenv("CRI_SOCKET")
	if GlobalCfg.CRISocket == "" {
		GlobalCfg.CRISocket = viper.GetString(ConfigCRISocket)
	}

	if GlobalCfg.CRISocket != "" && !strings.HasPrefix(GlobalCfg.CRISocket, "unix://") {
		return fmt.Errorf("CRI socket must start with 'unix://' (%s is invalid)", GlobalCfg.CRISocket)
	}

	GlobalCfg.NRISocket = os.Getenv("NRI_SOCKET")
	if GlobalCfg.NRISocket == "" {
		GlobalCfg.NRISocket = viper.GetString(ConfigNRISocket)
	}

	GlobalCfg.NRIIndex = viper.GetString(ConfigNRIIndex)

	GlobalCfg.Visibility = viper.GetString(ConfigVisibility)
	GlobalCfg.HostVisibility = viper.GetString(ConfigHostVisibility)

	GlobalCfg.Policy = viper.GetBool(ConfigKubearmorPolicy)
	GlobalCfg.HostPolicy = viper.GetBool(ConfigKubearmorHostPolicy)
	GlobalCfg.KVMAgent = viper.GetBool(ConfigKubearmorVM)
	GlobalCfg.K8sEnv = viper.GetBool(ConfigK8sEnv)

	GlobalCfg.Debug = viper.GetBool(ConfigDebug)

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

	GlobalCfg.ConfigUntrackedNs = strings.Split(viper.GetString(ConfigUntrackedNs), ",")

	GlobalCfg.LsmOrder = strings.Split(viper.GetString(LsmOrder), ",")

	GlobalCfg.BPFFsPath = viper.GetString(BPFFsPath)

	GlobalCfg.EnforcerAlerts = viper.GetBool(EnforcerAlerts)

	GlobalCfg.DefaultPostureLogs = viper.GetBool(ConfigDefaultPostureLogs)

	GlobalCfg.InitTimeout = viper.GetString(ConfigInitTimeout)

	GlobalCfg.StateAgent = viper.GetBool(ConfigStateAgent)

	kg.Printf("Final Configuration [%+v]", GlobalCfg)

	return nil
}
