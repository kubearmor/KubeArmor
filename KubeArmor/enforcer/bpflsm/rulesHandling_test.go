// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"strings"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// The BPF side folds queried names to lower case before the map lookup, so
// the rule key built from the policy must be lower case as well.
func TestBuildRuleListLowercasesDNSDomain(t *testing.T) {
	be := &BPFEnforcer{}

	policies := []tp.SecurityPolicy{
		{
			Metadata: map[string]string{"namespaceName": "multiubuntu"},
			Spec: tp.SecuritySpec{
				Network: tp.NetworkType{
					MatchDNSQueries: []tp.MatchDNSQueryType{
						{Domain: "Google.COM.", Action: "Block"},
					},
				},
			},
		},
	}

	rules := be.buildRuleList("", policies)

	var key InnerKey
	copy(key.Path[:], "google.com")
	val, ok := rules.NetworkRuleList[key]
	if !ok {
		t.Fatalf("expected a rule for google.com, got keys: %v", ruleKeys(rules.NetworkRuleList))
	}
	if val[NETWORK]&DENY == 0 {
		t.Fatalf("expected DENY on google.com, got %#x", val[NETWORK])
	}

	var mixed InnerKey
	copy(mixed.Path[:], "Google.COM")
	if _, ok := rules.NetworkRuleList[mixed]; ok {
		t.Fatalf("rule key must not keep the policy's mixed case")
	}
}

func ruleKeys(m map[InnerKey][2]uint16) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, strings.TrimRight(string(k.Path[:]), "\x00"))
	}
	return keys
}
