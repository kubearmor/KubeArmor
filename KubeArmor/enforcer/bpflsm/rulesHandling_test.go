// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestNetworkPortRuleHandling(t *testing.T) {
	be := &BPFEnforcer{
		ContainerMap: make(map[string]ContainerKV),
	}
	be.ContainerMap["test-c1"] = ContainerKV{
		Key: NsKey{PidNS: 1001, MntNS: 1002},
	}

	policies := []tp.SecurityPolicy{
		{
			Spec: tp.SecuritySpec{
				Network: tp.NetworkType{
					MatchProtocols: []tp.NetworkProtocolType{
						{
							Protocol: "tcp",
							Port:     80,
							Action:   "Block",
						},
						{
							Protocol: "udp",
							Port:     53,
							Action:   "Audit",
						},
						{
							Protocol: "tcp",
							Port:     8080,
							Action:   "Block",
							FromSource: []tp.MatchSourceType{
								{Path: "/usr/bin/curl"},
							},
						},
						{
							Port:   443,
							Action: "Block", // Protocol omitted -> should default to wildcard protocol 0
						},
					},
				},
			},
		},
	}

	rules := be.buildRuleList("test-c1", policies)

	// Check Port 80 Block rule
	var expectedPort80Key InnerKey
	expectedPort80Key.Path[0] = byte(PORT)
	expectedPort80Key.Path[1] = 0
	expectedPort80Key.Path[2] = 80
	expectedPort80Key.Path[3] = 6 // IPPROTO_TCP

	val, exists := rules.NetworkRuleList[expectedPort80Key]
	if !exists {
		t.Fatalf("expected port 80 rule not found in NetworkRuleList")
	}
	if (val[NETWORK] & DENY) == 0 {
		t.Errorf("expected port 80 rule to have DENY flag set, got %v", val[NETWORK])
	}

	// Check Port 53 Audit rule
	var expectedPort53Key InnerKey
	expectedPort53Key.Path[0] = byte(PORT)
	expectedPort53Key.Path[1] = 0
	expectedPort53Key.Path[2] = 53
	expectedPort53Key.Path[3] = 17 // IPPROTO_UDP

	val53, exists := rules.NetworkRuleList[expectedPort53Key]
	if !exists {
		t.Fatalf("expected port 53 rule not found in NetworkRuleList")
	}
	if (val53[NETWORK] & AUDIT) == 0 {
		t.Errorf("expected port 53 rule to have AUDIT flag set, got %v", val53[NETWORK])
	}

	// Check Port 8080 with FromSource
	var expectedPort8080Key InnerKey
	expectedPort8080Key.Path[0] = byte(PORT)
	expectedPort8080Key.Path[1] = byte((8080 >> 8) & 0xff)
	expectedPort8080Key.Path[2] = byte(8080 & 0xff)
	expectedPort8080Key.Path[3] = 6 // IPPROTO_TCP
	copy(expectedPort8080Key.Source[:], []byte("/usr/bin/curl"))

	val8080, exists := rules.NetworkRuleList[expectedPort8080Key]
	if !exists {
		t.Fatalf("expected port 8080 with fromSource rule not found in NetworkRuleList")
	}
	if (val8080[NETWORK] & DENY) == 0 {
		t.Errorf("expected port 8080 rule to have DENY flag set, got %v", val8080[NETWORK])
	}

	// Check Port 443 with omitted protocol (wildcard Path[3] == 0)
	var expectedPort443Key InnerKey
	expectedPort443Key.Path[0] = byte(PORT)
	expectedPort443Key.Path[1] = byte((443 >> 8) & 0xff)
	expectedPort443Key.Path[2] = byte(443 & 0xff)
	expectedPort443Key.Path[3] = 0 // wildcard protocol

	val443, exists := rules.NetworkRuleList[expectedPort443Key]
	if !exists {
		t.Fatalf("expected port 443 wildcard protocol rule not found in NetworkRuleList")
	}
	if (val443[NETWORK] & DENY) == 0 {
		t.Errorf("expected port 443 rule to have DENY flag set, got %v", val443[NETWORK])
	}
}

func TestNetworkIPRuleHandling(t *testing.T) {
	be := &BPFEnforcer{
		ContainerMap: make(map[string]ContainerKV),
	}
	be.ContainerMap["test-c2"] = ContainerKV{
		Key: NsKey{PidNS: 2001, MntNS: 2002},
	}

	policies := []tp.SecurityPolicy{
		{
			Spec: tp.SecuritySpec{
				Network: tp.NetworkType{
					MatchProtocols: []tp.NetworkProtocolType{
						{
							IP:     "192.168.1.100",
							Action: "Block",
						},
						{
							IP:     "10.0.0.1",
							Action: "Audit",
							FromSource: []tp.MatchSourceType{
								{Path: "/bin/nc"},
							},
						},
					},
				},
			},
		},
	}

	rules := be.buildRuleList("test-c2", policies)

	// Check IP 192.168.1.100 rule
	var expectedIPKey InnerKey
	expectedIPKey.Path[0] = byte(IP)
	expectedIPKey.Path[1] = 192
	expectedIPKey.Path[2] = 168
	expectedIPKey.Path[3] = 1
	expectedIPKey.Path[4] = 100

	val, exists := rules.NetworkRuleList[expectedIPKey]
	if !exists {
		t.Fatalf("expected IP rule for 192.168.1.100 not found in NetworkRuleList")
	}
	if (val[NETWORK] & DENY) == 0 {
		t.Errorf("expected IP rule to have DENY flag set, got %v", val[NETWORK])
	}

	// Check IP 10.0.0.1 with FromSource
	var expectedSourceIPKey InnerKey
	expectedSourceIPKey.Path[0] = byte(IP)
	expectedSourceIPKey.Path[1] = 10
	expectedSourceIPKey.Path[2] = 0
	expectedSourceIPKey.Path[3] = 0
	expectedSourceIPKey.Path[4] = 1
	copy(expectedSourceIPKey.Source[:], []byte("/bin/nc"))

	valSrc, exists := rules.NetworkRuleList[expectedSourceIPKey]
	if !exists {
		t.Fatalf("expected IP rule for 10.0.0.1 with fromSource not found in NetworkRuleList")
	}
	if (valSrc[NETWORK] & AUDIT) == 0 {
		t.Errorf("expected IP rule to have AUDIT flag set, got %v", valSrc[NETWORK])
	}
}

func TestBPFObjectSpecsLoad(t *testing.T) {
	// Verify enforcer eBPF ELF specs can be parsed by cilium/ebpf without errors
	spec, err := loadEnforcer()
	if err != nil {
		t.Fatalf("failed to load enforcer specs from eBPF object: %v", err)
	}

	// Verify the EnforceNetBind and other programs are in the spec
	if _, ok := spec.Programs["enforce_net_bind"]; !ok {
		t.Errorf("expected program enforce_net_bind not found in enforcer specs")
	}
	if _, ok := spec.Programs["enforce_net_connect"]; !ok {
		t.Errorf("expected program enforce_net_connect not found in enforcer specs")
	}
	if _, ok := spec.Programs["enforce_net_create"]; !ok {
		t.Errorf("expected program enforce_net_create not found in enforcer specs")
	}
	if _, ok := spec.Programs["enforce_net_accept"]; !ok {
		t.Errorf("expected program enforce_net_accept not found in enforcer specs")
	}

	// Verify enforcer_path eBPF ELF specs can be parsed as well
	pathSpec, err := loadEnforcer_path()
	if err != nil {
		t.Fatalf("failed to load enforcer_path specs from eBPF object: %v", err)
	}
	if pathSpec == nil {
		t.Fatalf("enforcer_path spec is nil")
	}
}
