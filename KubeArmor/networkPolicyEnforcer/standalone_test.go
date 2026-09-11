// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func newTestNetworkEnforcer(t *testing.T) *NetworkPolicyEnforcer {
	t.Helper()
	oldDebug := cfg.GlobalCfg.Debug
	cfg.GlobalCfg.Debug = false
	t.Cleanup(func() { cfg.GlobalCfg.Debug = oldDebug })
	ne := &NetworkPolicyEnforcer{
		Logger: &fd.Feeder{}, RulesLock: &sync.RWMutex{}, EndPointsLock: &sync.RWMutex{}, QuotasLock: &sync.Mutex{},
		QuotaTimers: map[string]*time.Ticker{}, QuotaCancel: map[string]context.CancelFunc{},
	}
	t.Cleanup(func() {
		ne.QuotasLock.Lock()
		defer ne.QuotasLock.Unlock()
		for name, timer := range ne.QuotaTimers {
			timer.Stop()
			ne.QuotaCancel[name]()
		}
	})
	return ne
}

func captureNFTables(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	capture := filepath.Join(dir, "rules.nft")
	t.Setenv("KUBEARMOR_NFT_CAPTURE", capture)
	// Capture the transaction passed to nft without touching the host firewall.
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\ncat \"$2\" > \"$KUBEARMOR_NFT_CAPTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return capture
}

func standaloneQuotaPolicy() tp.NetworkSecurityPolicy {
	return tp.NetworkSecurityPolicy{
		Metadata: map[string]string{"policyName": "quota-test-policy"},
		Spec: tp.NetworkSecuritySpec{
			Selector: tp.SelectorType{Identities: []string{"app=nginx"}}, Action: "Block", Level: "Policy",
			Egress: []tp.EgressType{{Limit: "2MB", Duration: "20m"}},
		},
	}
}

func TestUpdateNetworkSecurityPoliciesStandalone(t *testing.T) {
	for _, tt := range []struct {
		name         string
		podIP        string
		containerIPs []string
		level        string
		ingress      bool
		unmatched    bool
		wantIPs      []string
		wantQuotas   int
	}{
		{name: "standalone", containerIPs: []string{"172.18.0.2"}, level: "Policy", wantIPs: []string{"172.18.0.2"}, wantQuotas: 1},
		{name: "kubernetes IP takes precedence", podIP: "10.0.0.2", containerIPs: []string{"172.18.0.2"}, level: "Policy", wantIPs: []string{"10.0.0.2"}, wantQuotas: 1},
		{name: "shared quota", containerIPs: []string{"172.18.0.2", "172.18.0.3"}, level: "Policy", wantIPs: []string{"172.18.0.2", "172.18.0.3"}, wantQuotas: 1},
		{name: "individual quotas", containerIPs: []string{"172.18.0.2", "172.18.0.3"}, wantIPs: []string{"172.18.0.2", "172.18.0.3"}, wantQuotas: 2},
		{name: "duplicate IP", containerIPs: []string{"172.18.0.2", "172.18.0.2"}, wantIPs: []string{"172.18.0.2"}, wantQuotas: 1},
		{name: "IPv6 ingress", containerIPs: []string{"fd00::2"}, ingress: true, wantIPs: []string{"fd00::2"}, wantQuotas: 1},
		{name: "missing and invalid addresses", containerIPs: []string{"", "invalid"}},
		{name: "missing container"},
		{name: "unmatched selector", containerIPs: []string{"172.18.0.2"}, unmatched: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			capture := captureNFTables(t)
			ne := newTestNetworkEnforcer(t)
			ep := tp.EndPoint{EndPointName: "nginx", PodIP: tt.podIP, Identities: []string{"app=nginx"}, Containers: []string{"missing"}}
			containers := map[string]tp.Container{}
			for i, ip := range tt.containerIPs {
				id := string(rune('a' + i))
				ep.Containers = append(ep.Containers, id)
				containers[id] = tp.Container{ContainerID: id, ContainerIP: ip}
			}
			policy := standaloneQuotaPolicy()
			policy.Spec.Level = tt.level
			if tt.unmatched {
				policy.Spec.Selector.Identities = []string{"app=other"}
			}
			if tt.ingress {
				policy.Spec.Egress = nil
				policy.Spec.Ingress = []tp.IngressType{{Limit: "2MB", Duration: "20m"}}
			}
			ne.UpdateNetworkSecurityPolicies([]tp.NetworkSecurityPolicy{policy}, []tp.EndPoint{ep}, containers)
			if len(ne.ActiveQuotas) != tt.wantQuotas || len(ne.QuotaTimers) != tt.wantQuotas {
				t.Fatalf("quotas=%d timers=%d, want %d", len(ne.ActiveQuotas), len(ne.QuotaTimers), tt.wantQuotas)
			}
			data, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			if got := strings.Count(script, "add rule inet kubearmor FORWARD"); got != 2*len(tt.wantIPs) {
				t.Fatalf("forward rules=%d, want %d; transaction:\n%s", got, 2*len(tt.wantIPs), script)
			}
			direction, addr := "Egress", "saddr"
			if tt.ingress {
				direction, addr = "Ingress", "daddr"
			}
			for i, ip := range tt.wantIPs {
				family := "ip"
				if strings.Contains(ip, ":") {
					family = "ip6"
				}
				if !strings.Contains(script, family+" "+addr+" "+ip+" quota name") {
					t.Errorf("missing quota rule for %s:\n%s", ip, script)
				}
				info := packetInfo{srcIP: ip, dstIP: ip}
				log := ne.buildKubeArmorLog(info, "", []string{"quota-test-policy", direction, "Block", "policy", "2MB"})
				if log.PodName != "nginx" {
					t.Errorf("missing endpoint metadata for %s: %+v", ip, log)
				}
				if tt.podIP == "" && len(tt.containerIPs) == len(tt.wantIPs) && log.ContainerID != string(rune('a'+i)) {
					t.Errorf("wrong container attribution for %s: %s", ip, log.ContainerID)
				}
			}
			if ep.PodIP != tt.podIP || len(ep.Containers) != len(tt.containerIPs)+1 {
				t.Fatal("input endpoint was mutated")
			}
		})
	}
}

func TestStandaloneQuotaLifecycle(t *testing.T) {
	capture := captureNFTables(t)
	ne := newTestNetworkEnforcer(t)
	policies := []tp.NetworkSecurityPolicy{standaloneQuotaPolicy()}
	endpoints := []tp.EndPoint{{EndPointName: "nginx", Identities: []string{"app=nginx"}, Containers: []string{"nginx"}}}
	containers := map[string]tp.Container{}
	update := func(wantIP string, wantQuota bool) {
		t.Helper()
		ne.UpdateNetworkSecurityPolicies(policies, endpoints, containers)
		data, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		wantCount := 0
		if wantQuota {
			wantCount = 1
		}
		if len(ne.ActiveQuotas) != wantCount || len(ne.QuotaTimers) != wantCount {
			t.Fatalf("quotas=%d timers=%d, want %d", len(ne.ActiveQuotas), len(ne.QuotaTimers), wantCount)
		}
		if wantIP != "" && !strings.Contains(string(data), "ip saddr "+wantIP+" quota name") {
			t.Fatalf("missing rule for %s", wantIP)
		}
	}
	update("", false) // Policy arrives before the container.
	containers["nginx"] = tp.Container{ContainerIP: "172.18.0.2"}
	update("172.18.0.2", true)
	quotaName := "quota_quota_test_policy_Egress_0"
	timer := ne.QuotaTimers[quotaName]
	update("172.18.0.2", true)
	if ne.QuotaTimers[quotaName] != timer {
		t.Fatal("unchanged quota window was reset")
	}
	containers["nginx"] = tp.Container{ContainerIP: "172.18.0.3"}
	update("172.18.0.3", true)
	if _, ok := ne.EndPoints["172.18.0.2"]; ok {
		t.Fatal("stale endpoint IP retained")
	}
	delete(containers, "nginx")
	update("", false)
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "delete quota inet kubearmor "+quotaName) {
		t.Fatal("stale quota was not deleted")
	}
	containers["nginx"] = tp.Container{ContainerIP: "172.18.0.4"}
	update("172.18.0.4", true)
	policies = nil
	update("", false)
}
