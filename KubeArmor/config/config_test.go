// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package config

import (
	"flag"
	"os"
	"testing"

	"github.com/spf13/viper"
)

// resetState provides complete isolation for the config package tests.
// It resets the flag.CommandLine singleton to avoid "flag redefined" panics,
// clears Viper state, resets the GlobalCfg struct, and restores os.Args.
func resetState(t *testing.T) {
	oldCommandLine := flag.CommandLine
	oldArgs := os.Args

	t.Cleanup(func() {
		viper.Reset()
		GlobalCfg = KubearmorConfig{}
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
		os.Unsetenv("CRI_SOCKET")
		os.Unsetenv("KUBEARMOR_CFG")
	})

	// Pre-test clear: ensure no env pollution from a previous subtest whose t.Setenv
	// registered cleanup on an outer *testing.T scope and hasn't fired yet.
	os.Unsetenv("CRI_SOCKET")
	os.Unsetenv("KUBEARMOR_CFG")

	// Inject fresh flag set to avoid 'flag redefined' panic on repeated parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = []string{"kubearmor"} // Default mock args
}

// TestConstants_Values verifies that the string values of config key constants
// match the keys used in kubearmor.yaml config files and Viper lookups.
// These are external API surface: silently renaming a constant value would
// break all production kubearmor.yaml files without a compile-time error.
func TestConstants_Values(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"ConfigCluster", ConfigCluster, "cluster"},
		{"ConfigHost", ConfigHost, "host"},
		{"ConfigGRPC", ConfigGRPC, "gRPC"},
		{"ConfigGRPCHealthPort", ConfigGRPCHealthPort, "gRPCHealthPort"},
		{"ConfigTLSCertPath", ConfigTLSCertPath, "tlsCertPath"},
		{"ConfigTLSCertProvider", ConfigTLSCertProvider, "tlsCertProvider"},
		{"SelfCertProvider", SelfCertProvider, "self"},
		{"ExternalCertProvider", ExternalCertProvider, "external"},
		{"ConfigTLS", ConfigTLS, "tlsEnabled"},
		{"ConfigLogPath", ConfigLogPath, "logPath"},
		{"ConfigSELinuxProfileDir", ConfigSELinuxProfileDir, "seLinuxProfileDir"},
		{"ConfigCRISocket", ConfigCRISocket, "criSocket"},
		{"ConfigNRISocket", ConfigNRISocket, "nriSocket"},
		{"ConfigNRIIndex", ConfigNRIIndex, "nriIndex"},
		{"ConfigNRI", ConfigNRI, "enableNRI"},
		{"ConfigVisibility", ConfigVisibility, "visibility"},
		{"ConfigHostVisibility", ConfigHostVisibility, "hostVisibility"},
		{"ConfigKubearmorPolicy", ConfigKubearmorPolicy, "enableKubeArmorPolicy"},
		{"ConfigKubearmorHostPolicy", ConfigKubearmorHostPolicy, "enableKubeArmorHostPolicy"},
		{"ConfigKubearmorVM", ConfigKubearmorVM, "enableKubeArmorVm"},
		{"ConfigDefaultFilePosture", ConfigDefaultFilePosture, "defaultFilePosture"},
		{"ConfigDefaultNetworkPosture", ConfigDefaultNetworkPosture, "defaultNetworkPosture"},
		{"ConfigDefaultCapabilitiesPosture", ConfigDefaultCapabilitiesPosture, "defaultCapabilitiesPosture"},
		{"ConfigHostDefaultFilePosture", ConfigHostDefaultFilePosture, "hostDefaultFilePosture"},
		{"ConfigHostDefaultNetworkPosture", ConfigHostDefaultNetworkPosture, "hostDefaultNetworkPosture"},
		{"ConfigHostDefaultCapabilitiesPosture", ConfigHostDefaultCapabilitiesPosture, "hostDefaultCapabilitiesPosture"},
		{"ConfigHostDefaultDevicePosture", ConfigHostDefaultDevicePosture, "hostDefaultDevicePosture"},
		{"ConfigCoverageTest", ConfigCoverageTest, "coverageTest"},
		{"ConfigK8sEnv", ConfigK8sEnv, "k8s"},
		{"ConfigDebug", ConfigDebug, "debug"},
		{"ConfigUntrackedNs", ConfigUntrackedNs, "untrackedNs"},
		{"LsmOrder", LsmOrder, "lsm"},
		{"BPFFsPath", BPFFsPath, "bpfFsPath"},
		{"EnforcerAlerts", EnforcerAlerts, "enforcerAlerts"},
		{"ConfigDefaultPostureLogs", ConfigDefaultPostureLogs, "defaultPostureLogs"},
		{"ConfigInitTimeout", ConfigInitTimeout, "initTimeout"},
		{"ConfigStateAgent", ConfigStateAgent, "enableKubeArmorStateAgent"},
		{"ConfigAlertThrottling", ConfigAlertThrottling, "alertThrottling"},
		{"ConfigMaxAlertPerSec", ConfigMaxAlertPerSec, "maxAlertPerSec"},
		{"ConfigThrottleSec", ConfigThrottleSec, "throttleSec"},
		{"ConfigAnnotateResources", ConfigAnnotateResources, "annotateResources"},
		{"ConfigProcFsMount", ConfigProcFsMount, "procfsMount"},
		{"ConfigDropResourceFromProcessLogs", ConfigDropResourceFromProcessLogs, "dropResourceFromProcessLogs"},
		{"ConfigMachineIDPath", ConfigMachineIDPath, "machineIDPath"},
		{"UseOCIHooks", UseOCIHooks, "useOCIHooks"},
		{"ConfigEnableIma", ConfigEnableIma, "enableIMA"},
		{"ConfigUSBDeviceHandler", ConfigUSBDeviceHandler, "enableUSBDeviceHandler"},
		{"ConfigArgMatching", ConfigArgMatching, "matchArgs"},
		{"ConfigNetworkPolicyEnforcer", ConfigNetworkPolicyEnforcer, "enableNetworkPolicyEnforcer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Expected constant %s to be '%s', got '%s'", tt.name, tt.expected, tt.constant)
			}
		})
	}
}

func TestLoadDynamicConfig(t *testing.T) {
	tests := []struct {
		name     string
		setup    func()
		validate func(t *testing.T)
	}{
		{
			name: "Default HostVisibility in K8s",
			setup: func() {
				viper.Set(ConfigHostVisibility, "default")
				GlobalCfg.KVMAgent = false
				GlobalCfg.K8sEnv = true
				viper.Set(ConfigAlertThrottling, true)
				viper.Set(ConfigNetworkPolicyEnforcer, true)
			},
			validate: func(t *testing.T) {
				if GlobalCfg.HostVisibility != "none" {
					t.Errorf("Expected HostVisibility 'none', got '%s'", GlobalCfg.HostVisibility)
				}
				if !GlobalCfg.AlertThrottling {
					t.Errorf("Expected AlertThrottling to be true")
				}
				if !GlobalCfg.NetworkPolicyEnforcer {
					t.Errorf("Expected NetworkPolicyEnforcer to be true")
				}
			},
		},
		{
			name: "KVMAgent Override",
			setup: func() {
				viper.Set(ConfigHostVisibility, "default")
				GlobalCfg.KVMAgent = true
				viper.Set(ConfigAlertThrottling, false)
			},
			validate: func(t *testing.T) {
				if GlobalCfg.HostVisibility != "process,file,network,capabilities" {
					t.Errorf("Expected HostVisibility 'process,file,network,capabilities', got '%s'", GlobalCfg.HostVisibility)
				}
				if GlobalCfg.AlertThrottling {
					t.Errorf("Expected AlertThrottling to be false when explicitly disabled")
				}
			},
		},
		{
			name: "Non-K8s HostPolicy Override",
			setup: func() {
				viper.Set(ConfigHostVisibility, "default")
				GlobalCfg.K8sEnv = false
				GlobalCfg.HostPolicy = true
			},
			validate: func(t *testing.T) {
				if GlobalCfg.HostVisibility != "process,file,network,capabilities" {
					t.Errorf("Expected HostVisibility 'process,file,network,capabilities', got '%s'", GlobalCfg.HostVisibility)
				}
			},
		},
		{
			name: "User specified visibility",
			setup: func() {
				viper.Set(ConfigHostVisibility, "process,file")
			},
			validate: func(t *testing.T) {
				if GlobalCfg.HostVisibility != "process,file" {
					t.Errorf("Expected HostVisibility 'process,file', got '%s'", GlobalCfg.HostVisibility)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetState(t)
			tt.setup()
			LoadDynamicConfig()
			tt.validate(t)
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T)
		expectError bool
		validate    func(t *testing.T)
	}{
		{
			name: "Valid CRI Socket (unix://)",
			setup: func(t *testing.T) {
				t.Setenv("CRI_SOCKET", "unix:///run/containerd.sock")
			},
			expectError: false,
			validate: func(t *testing.T) {
				if GlobalCfg.CRISocket != "unix:///run/containerd.sock" {
					t.Errorf("Expected CRI_SOCKET to be unix:///run/containerd.sock, got %s", GlobalCfg.CRISocket)
				}
			},
		},
		{
			name: "Invalid CRI Socket (tcp://)",
			setup: func(t *testing.T) {
				t.Setenv("CRI_SOCKET", "tcp://127.0.0.1:2375")
			},
			expectError: true,
			validate:    func(t *testing.T) {},
		},
		{
			name: "KVMAgent Overrides Policy",
			setup: func(t *testing.T) {
				viper.Set(ConfigKubearmorVM, true)
			},
			expectError: false,
			validate: func(t *testing.T) {
				if GlobalCfg.Policy {
					t.Errorf("KVMAgent=true should disable container Policy, got Policy=true")
				}
				if !GlobalCfg.HostPolicy {
					t.Errorf("KVMAgent=true should enable HostPolicy, got HostPolicy=false")
				}
			},
		},
		{
			name: "Valid YAML Config Load",
			setup: func(t *testing.T) {
				tmpfile, err := os.CreateTemp("", "kubearmor-*.yaml")
				if err != nil {
					t.Fatal(err)
				}
				// Ensure the file is removed even if validate() calls t.Fatal
				t.Cleanup(func() { os.Remove(tmpfile.Name()) })

				yamlContent := []byte(`cluster: test-cluster
gRPC: "32768"
tlsEnabled: true
lsm: "bpf,selinux"
nriSocket: "unix:///var/run/nri/nri.sock"`)
				if _, err := tmpfile.Write(yamlContent); err != nil {
					t.Fatal(err)
				}
				tmpfile.Close()

				t.Setenv("KUBEARMOR_CFG", tmpfile.Name())
			},
			expectError: false,
			validate: func(t *testing.T) {
				if GlobalCfg.Cluster != "test-cluster" {
					t.Errorf("Expected Cluster to be test-cluster, got %s", GlobalCfg.Cluster)
				}
				if GlobalCfg.GRPC != "32768" {
					t.Errorf("Expected GRPC to be 32768, got %s", GlobalCfg.GRPC)
				}
				if !GlobalCfg.TLSEnabled {
					t.Errorf("Expected TLSEnabled to be true")
				}
				if len(GlobalCfg.LsmOrder) != 2 || GlobalCfg.LsmOrder[0] != "bpf" || GlobalCfg.LsmOrder[1] != "selinux" {
					t.Errorf("Expected LsmOrder [bpf, selinux], got %v", GlobalCfg.LsmOrder)
				}
				if GlobalCfg.NRISocket != "unix:///var/run/nri/nri.sock" {
					t.Errorf("Expected NRISocket to be unix:///var/run/nri/nri.sock, got %s", GlobalCfg.NRISocket)
				}
			},
		},
		{
			name: "Empty YAML Config Fallbacks",
			setup: func(t *testing.T) {
				tmpfile, err := os.CreateTemp("", "kubearmor-*.yaml")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Remove(tmpfile.Name()) })

				// Write an empty config to force all fallbacks
				if _, err := tmpfile.Write([]byte(`{}`)); err != nil {
					t.Fatal(err)
				}
				tmpfile.Close()

				t.Setenv("KUBEARMOR_CFG", tmpfile.Name())
			},
			expectError: false,
			validate: func(t *testing.T) {
				if GlobalCfg.Cluster != "default" {
					t.Errorf("Expected Cluster fallback to be 'default', got %s", GlobalCfg.Cluster)
				}
			},
		},
		{
			name: "Invalid YAML Config Load",
			setup: func(t *testing.T) {
				tmpfile, err := os.CreateTemp("", "kubearmor-*.yaml")
				if err != nil {
					t.Fatal(err)
				}
				// Ensure the file is removed even if test fatals
				t.Cleanup(func() { os.Remove(tmpfile.Name()) })

				yamlContent := []byte(`cluster: [malformed`)
				if _, err := tmpfile.Write(yamlContent); err != nil {
					t.Fatal(err)
				}
				tmpfile.Close()

				t.Setenv("KUBEARMOR_CFG", tmpfile.Name())
			},
			expectError: true,
			validate:    func(t *testing.T) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetState(t)
			tt.setup(t)

			err := LoadConfig()

			if tt.expectError && err == nil {
				t.Errorf("Expected an error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			tt.validate(t)
		})
	}
}

// TestLoadConfig_CLIArgs verifies that CLI arguments passed via os.Args are
// correctly parsed by readCmdLineParams() and propagated to GlobalCfg through LoadConfig().
func TestLoadConfig_CLIArgs(t *testing.T) {
	resetState(t)

	// Inject arbitrary flags
	os.Args = []string{"kubearmor", "-cluster=cli-cluster", "-gRPC=1234"}

	err := LoadConfig()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if GlobalCfg.Cluster != "cli-cluster" {
		t.Errorf("Expected Cluster from CLI args to be cli-cluster, got %s", GlobalCfg.Cluster)
	}
	if GlobalCfg.GRPC != "1234" {
		t.Errorf("Expected GRPC from CLI args to be 1234, got %s", GlobalCfg.GRPC)
	}
}
