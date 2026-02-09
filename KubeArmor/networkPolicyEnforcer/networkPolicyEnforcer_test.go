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
		name       string
		chain      string
		peers      []tp.NetworkPeer
		ports      []tp.PortType
		ifaces     []string
		action     string
		policyName string
		expected   []NetworkRule
	}{
		{
			name:       "Single Port Allow",
			chain:      "INPUT",
			peers:      nil,
			ports:      []tp.PortType{{Port: "80", Protocol: "TCP"}},
			ifaces:     nil,
			action:     "Allow",
			policyName: "test-allow",
			expected: []NetworkRule{
				{TableFamily: "ip", Chain: "INPUT", RuleContent: "tcp dport 80 accept"},
			},
		},
		{
			name:       "Port Range with CIDR Block",
			chain:      "OUTPUT",
			peers:      []tp.NetworkPeer{{IPBlock: &tp.IPBlock{CIDR: "192.168.1.0/24"}}},
			ports:      []tp.PortType{{Port: "3000", EndPort: ptr.To(int32(4000)), Protocol: "UDP"}},
			ifaces:     nil,
			action:     "Block",
			policyName: "test-block",
			expected: []NetworkRule{
				{TableFamily: "ip", Chain: "OUTPUT", RuleContent: "ip daddr 192.168.1.0/24 udp dport 3000-4000 log prefix \"test-block OUTPUT Block\" group 0 drop"},
			},
		},
		{
			name:       "IPv6 with Interface Audit",
			chain:      "INPUT",
			peers:      []tp.NetworkPeer{{IPBlock: &tp.IPBlock{CIDR: "fe80::/10"}}},
			ports:      []tp.PortType{{Port: "ssh"}}, // missing protocol should default to tcp, ssh should resolve to 22
			ifaces:     []string{"eth0"},
			action:     "Audit",
			policyName: "test-audit",
			expected: []NetworkRule{
				{TableFamily: "ip6", Chain: "INPUT", RuleContent: "iifname \"eth0\" ip6 saddr fe80::/10 tcp dport 22 log prefix \"test-audit INPUT Audit\" group 0 accept"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := generateRules(tt.chain, tt.peers, tt.ports, tt.ifaces, tt.action, tt.policyName)

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
					t.Errorf("expected RuleContent:\n%s\ngot:\n%s", tt.expected[i].RuleContent, r.RuleContent)
				}
			}
		})
	}
}
