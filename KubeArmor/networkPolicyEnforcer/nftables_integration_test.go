// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	_ "embed"
	"os"
	"os/exec"
	"strings"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:embed testdata/quota_traffic.py
var quotaTrafficScript string

// Run only in a disposable network namespace with nft and CAP_NET_ADMIN.
// KUBEARMOR_TEST_TRAFFIC=1 additionally requires ip, python3, and CAP_NET_RAW
// to check actual packet verdicts and quota accounting through veth/dummy links.
func TestNetworkQuotaNFTables(t *testing.T) {
	if os.Getenv("KUBEARMOR_TEST_NFTABLES") != "1" {
		t.Skip("set KUBEARMOR_TEST_NFTABLES=1 inside a disposable network namespace")
	}
	nft := func(t *testing.T, args ...string) string {
		t.Helper()
		output, err := exec.Command("nft", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("nft %v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	for _, target := range []string{"host", "container"} {
		t.Run(target, func(t *testing.T) {
			ne := newTestNetworkEnforcer(t)
			policy := standaloneQuotaPolicy()
			if target == "host" {
				policy.Metadata["policyName"] = "host-egress-quota"
				policy.Spec.Selector = tp.SelectorType{}
				policy.Spec.Level = ""
				policy.Spec.Action = "Audit"
				policy.Spec.Egress = []tp.EgressType{{Limit: "4MB", Duration: "1m"}}
			}
			endpoints := []tp.EndPoint{{EndPointName: "nginx", Identities: []string{"app=nginx"}, Containers: []string{"nginx"}}}
			containers := map[string]tp.Container{"nginx": {ContainerIP: "172.18.0.2"}}
			ne.UpdateNetworkSecurityPolicies([]tp.NetworkSecurityPolicy{policy}, endpoints, containers)
			rules := nft(t, "list", "table", "inet", "kubearmor")
			quotaName := sanitizeQuotaName("quota_" + policy.Metadata["policyName"] + "_Egress_0")
			if !strings.Contains(rules, "quota "+quotaName+" {") {
				t.Fatalf("quota missing:\n%s", rules)
			}
			if target == "container" && !strings.Contains(rules, "ip saddr 172.18.0.2 quota name") {
				t.Fatalf("container rule missing:\n%s", rules)
			}
			if target == "host" && !strings.Contains(rules, `host-egress-quota Egress Audit host 4MB`) {
				t.Fatalf("host audit rule missing:\n%s", rules)
			}
			if os.Getenv("KUBEARMOR_TEST_TRAFFIC") == "1" {
				output, err := exec.Command("python3", "-c", quotaTrafficScript, target, quotaName).CombinedOutput()
				if err != nil {
					t.Fatalf("quota traffic verification: %v\n%s", err, output)
				}
				t.Logf("traffic verification: %s", output)
			}
			nft(t, "reset", "quota", "inet", "kubearmor", quotaName)
			ne.UpdateNetworkSecurityPolicies(nil, nil, nil)
			if rules = nft(t, "list", "table", "inet", "kubearmor"); strings.Contains(rules, quotaName) {
				t.Fatalf("deleted quota remains:\n%s", rules)
			}
		})
	}
}
