// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"fmt"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"k8s.io/utils/ptr"
)

func TestGetProtocolName(t *testing.T) {
	tests := []struct {
		protocol uint8
		expected string
	}{
		{1, "ICMP"},
		{6, "TCP"},
		{17, "UDP"},
		{58, "ICMPv6"},
		{132, "SCTP"},
		{99, "Proto-99"}, // fallback case
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Proto-%d", tt.protocol), func(t *testing.T) {
			result := getProtocolName(tt.protocol)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestResolvePort(t *testing.T) {
	tests := []struct {
		port     string
		expected string
	}{
		{"80", "80"},
		{"http", "80"},
		{"HTTP", "80"}, // test case insensitivity
		{"ssh", "22"},
		{"https", "443"},
		{"dns", "53"},
		{"unknown-svc", "unknown-svc"}, // fallback to original string
	}

	for _, tt := range tests {
		t.Run(tt.port, func(t *testing.T) {
			result := resolvePort(tt.port)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGenerateRules(t *testing.T) {
	tests := []struct {
		name        string
		direction   string
		peers       []tp.NetworkPeer
		ports       []tp.PortType
		ifaces      []string
		action      string
		policyName  string
		limit       string
		duration    string
		ruleIdx     int
		podIPs      []string
		isPodPolicy bool
		policyLevel string
		expected    []NetworkRule
	}{
		{
			name:        "Single Port Allow",
			direction:   "Ingress",
			peers:       nil,
			ports:       []tp.PortType{{Port: "80", Protocol: "TCP"}},
			ifaces:      nil,
			action:      "Allow",
			policyName:  "test-allow",
			limit:       "",
			duration:    "",
			ruleIdx:     0,
			podIPs:      nil,
			isPodPolicy: false,
			policyLevel: "pod",
			expected: []NetworkRule{
				{TableFamily: "ip", Chain: "INPUT", RuleContent: "tcp dport 80 accept"},
				{TableFamily: "ip6", Chain: "INPUT", RuleContent: "tcp dport 80 accept"},
			},
		},
		{
			name:        "Port Range with CIDR Block",
			direction:   "Egress",
			peers:       []tp.NetworkPeer{{IPBlock: &tp.IPBlock{CIDR: "192.168.1.0/24"}}},
			ports:       []tp.PortType{{Port: "3000", EndPort: ptr.To(int32(4000)), Protocol: "UDP"}},
			ifaces:      nil,
			action:      "Block",
			policyName:  "test-block",
			limit:       "",
			duration:    "",
			ruleIdx:     0,
			podIPs:      nil,
			isPodPolicy: false,
			policyLevel: "pod",
			expected: []NetworkRule{
				{TableFamily: "ip", Chain: "OUTPUT", RuleContent: "ip daddr 192.168.1.0/24 udp dport 3000-4000 log prefix \"test-block Egress Block host\" group 0 drop"},
				{TableFamily: "ip6", Chain: "OUTPUT", RuleContent: "udp dport 3000-4000 log prefix \"test-block Egress Block host\" group 0 drop"},
			},
		},
		{
			name:        "IPv6 with Interface Audit",
			direction:   "Ingress",
			peers:       []tp.NetworkPeer{{IPBlock: &tp.IPBlock{CIDR: "fe80::/10"}}},
			ports:       []tp.PortType{{Port: "ssh"}}, // missing protocol should default to tcp, ssh should resolve to 22
			ifaces:      []string{"eth0"},
			action:      "Audit",
			policyName:  "test-audit",
			limit:       "",
			duration:    "",
			ruleIdx:     0,
			podIPs:      nil,
			isPodPolicy: false,
			policyLevel: "pod",
			expected: []NetworkRule{
				{TableFamily: "ip", Chain: "INPUT", RuleContent: "iifname \"eth0\" tcp dport 22 log prefix \"test-audit Ingress Audit host\" group 0 accept"},
				{TableFamily: "ip6", Chain: "INPUT", RuleContent: "iifname \"eth0\" ip6 saddr fe80::/10 tcp dport 22 log prefix \"test-audit Ingress Audit host\" group 0 accept"},
			},
		},
		{
			name:        "Pod-level Quota",
			direction:   "Egress",
			peers:       nil,
			ports:       nil,
			ifaces:      nil,
			action:      "Block",
			policyName:  "pod-egress",
			limit:       "5MB",
			duration:    "16h",
			ruleIdx:     0,
			podIPs:      []string{"10.0.0.1", "10.0.0.2"},
			isPodPolicy: true,
			policyLevel: "pod",
			expected: []NetworkRule{
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.1 quota name \"quota_pod_egress_Egress_0_10_0_0_1\" log prefix \"pod-egress Egress Block pod 5MB\" group 0 drop"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.1 accept"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.2 quota name \"quota_pod_egress_Egress_0_10_0_0_2\" log prefix \"pod-egress Egress Block pod 5MB\" group 0 drop"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.2 accept"},
			},
		},
		{
			name:        "Policy-level Quota",
			direction:   "Egress",
			peers:       nil,
			ports:       nil,
			ifaces:      nil,
			action:      "Block",
			policyName:  "policy-egress",
			limit:       "5MB",
			duration:    "16h",
			ruleIdx:     0,
			podIPs:      []string{"10.0.0.1", "10.0.0.2"},
			isPodPolicy: true,
			policyLevel: "policy",
			expected: []NetworkRule{
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.1 quota name \"quota_policy_egress_Egress_0\" log prefix \"policy-egress Egress Block policy 5MB\" group 0 drop"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.1 accept"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.2 quota name \"quota_policy_egress_Egress_0\" log prefix \"policy-egress Egress Block policy 5MB\" group 0 drop"},
				{TableFamily: "inet", Chain: "FORWARD", RuleContent: "ip saddr 10.0.0.2 accept"},
			},
		},
		{
			name:        "Host-level Global Quota",
			direction:   "Egress",
			peers:       nil,
			ports:       nil,
			ifaces:      []string{"eth0"}, // interface should be ignored for global host quota
			action:      "Block",
			policyName:  "host-egress",
			limit:       "500MB",
			duration:    "24h",
			ruleIdx:     0,
			podIPs:      nil,
			isPodPolicy: false,
			policyLevel: "host",
			expected: []NetworkRule{
				{TableFamily: "inet", Chain: "OUTPUT", RuleContent: "quota name \"quota_host_egress_Egress_0\" log prefix \"host-egress Egress Block host 500MB\" group 0 drop"},
				{TableFamily: "inet", Chain: "OUTPUT", RuleContent: "accept"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var quotas []QuotaObj
			rules := generateRules(tt.direction, tt.peers, tt.ports, tt.ifaces, tt.action, tt.policyName, tt.limit, tt.duration, tt.ruleIdx, &quotas, tt.podIPs, tt.isPodPolicy, tt.policyLevel)

			if len(rules) != len(tt.expected) {
				t.Fatalf("expected %d rules, got %d", len(tt.expected), len(rules))
			}

			for i, r := range rules {
				if r.TableFamily != tt.expected[i].TableFamily {
					t.Errorf("expected TableFamily %s, got %s", tt.expected[i].TableFamily, r.TableFamily)
				}
				if r.Chain != tt.expected[i].Chain {
					t.Errorf("expected Chain %s, got %s", tt.expected[i].Chain, r.Chain)
				}
				if r.RuleContent != tt.expected[i].RuleContent {
					t.Errorf("expected RuleContent:\n%q\ngot:\n%q", tt.expected[i].RuleContent, r.RuleContent)
				}
			}
		})
	}
}
