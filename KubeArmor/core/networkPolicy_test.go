// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	ne "github.com/kubearmor/KubeArmor/KubeArmor/networkPolicyEnforcer"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestContainerRemovalUpdatesNetworkPolicies(t *testing.T) {
	oldNetwork, oldState, oldDebug := cfg.GlobalCfg.NetworkPolicyEnforcer, cfg.GlobalCfg.StateAgent, cfg.GlobalCfg.Debug
	cfg.GlobalCfg.NetworkPolicyEnforcer, cfg.GlobalCfg.StateAgent, cfg.GlobalCfg.Debug = true, false, false
	oldDocker, oldContainerd := Docker, Containerd
	Docker, Containerd = &DockerHandler{}, &ContainerdHandler{}
	t.Cleanup(func() {
		cfg.GlobalCfg.NetworkPolicyEnforcer, cfg.GlobalCfg.StateAgent, cfg.GlobalCfg.Debug = oldNetwork, oldState, oldDebug
		Docker, Containerd = oldDocker, oldContainerd
	})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, runtime := range []string{"docker", "containerd"} {
		t.Run(runtime, func(t *testing.T) {
			dm := NewKubeArmorDaemon()
			dm.Logger = &fd.Feeder{SecurityPolicies: map[string]tp.MatchPolicies{}, SecurityPoliciesLock: &sync.RWMutex{}}
			dm.Logger.Node = &dm.Node
			dm.NetworkPolicyEnforcer = &ne.NetworkPolicyEnforcer{
				Logger: dm.Logger, RulesLock: &sync.RWMutex{}, EndPointsLock: &sync.RWMutex{}, QuotasLock: &sync.Mutex{},
				QuotaTimers: map[string]*time.Ticker{}, QuotaCancel: map[string]context.CancelFunc{},
			}
			enforcer := dm.NetworkPolicyEnforcer
			t.Cleanup(func() {
				enforcer.QuotasLock.Lock()
				defer enforcer.QuotasLock.Unlock()
				for name, timer := range enforcer.QuotaTimers {
					timer.Stop()
					enforcer.QuotaCancel[name]()
				}
			})
			dm.Containers["nginx"] = tp.Container{
				ContainerID: "nginx", ContainerName: "nginx", ContainerIP: "172.18.0.2", NamespaceName: "container_namespace", Labels: "app=nginx",
			}
			dm.EndPoints = []tp.EndPoint{{EndPointName: "nginx", NamespaceName: "container_namespace", Containers: []string{"nginx"}, Identities: []string{"app=nginx"}}}
			dm.NetworkSecurityPolicies = []tp.NetworkSecurityPolicy{{
				Metadata: map[string]string{"policyName": "quota-test-policy"},
				Spec: tp.NetworkSecuritySpec{
					Selector: tp.SelectorType{Identities: []string{"app=nginx"}}, Action: "Block", Level: "Policy",
					Egress: []tp.EgressType{{Limit: "2MB", Duration: "20m"}},
				},
			}}
			dm.UpdateNetworkSecurityPolicies()
			if len(enforcer.ActiveQuotas) != 1 {
				t.Fatal("initial quota was not created")
			}
			if runtime == "docker" {
				dm.UpdateDockerContainer("nginx", "destroy")
			} else if err := dm.UpdateContainerdContainer(context.Background(), "nginx", 0, "destroy"); err != nil {
				t.Fatal(err)
			}
			if len(enforcer.ActiveQuotas) != 0 || len(enforcer.QuotaTimers) != 0 || len(enforcer.EndPoints) != 0 {
				t.Fatal("container removal left stale network policy state")
			}
			for _, rule := range enforcer.Rules {
				if rule.Chain == "FORWARD" {
					t.Fatalf("container removal left forwarding rule: %+v", rule)
				}
			}
		})
	}
}
