package feeder

import (
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func newNetworkPolicyFeeder(policyResource, action string) *Feeder {
	fd := &Feeder{
		BaseFeeder: BaseFeeder{
			Node:         &tp.Node{},
			Enforcer:     "BPFLSM",
			EnforcerLock: new(sync.RWMutex),
		},
		SecurityPolicies:     map[string]tp.MatchPolicies{},
		SecurityPoliciesLock: new(sync.RWMutex),
		DefaultPostures:      map[string]tp.DefaultPosture{},
		DefaultPosturesLock:  new(sync.Mutex),
	}
	fd.SecurityPolicies["default_test-pod"] = tp.MatchPolicies{
		Policies: []tp.MatchPolicy{
			{
				PolicyName:   "ksp-network-policy",
				Severity:     "8",
				Operation:    "Network",
				ResourceType: "Protocol",
				Resource:     policyResource,
				Action:       action,
			},
		},
	}
	return fd
}

func networkLog(resource, result string) tp.Log {
	return tp.Log{
		NamespaceName: "default",
		PodName:       "test-pod",
		Operation:     "Network",
		Resource:      resource,
		Result:        result,
		PolicyEnabled: tp.KubeArmorPolicyEnabled,
	}
}

func TestFetchAddressFamily(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{
			name:     "extracts address family",
			resource: "domain=AF_RDS type=SOCK_SEQPACKET protocol=0",
			want:     "af_rds",
		},
		{
			name:     "lowercases family value",
			resource: "domain=AF_INET type=SOCK_STREAM protocol=TCP",
			want:     "af_inet",
		},
		{
			name:     "missing domain token",
			resource: "protocol=TCP type=SOCK_STREAM",
			want:     "",
		},
		{
			name:     "domain token can appear after other fields",
			resource: "type=SOCK_RAW domain=AF_PACKET protocol=0",
			want:     "af_packet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fetchAddressFamily(tt.resource); got != tt.want {
				t.Fatalf("fetchAddressFamily() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchProtocol(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
	}{
		{
			name:     "tcp stream",
			resource: "protocol=TCP type=SOCK_STREAM",
			want:     "tcp",
		},
		{
			name:     "udp datagram",
			resource: "protocol=UDP type=SOCK_DGRAM",
			want:     "udp",
		},
		{
			name:     "raw socket type",
			resource: "type=SOCK_RAW protocol=HOPOPT",
			want:     "raw",
		},
		{
			name:     "unknown resource falls through",
			resource: "domain=AF_RDS",
			want:     "domain=AF_RDS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fetchProtocol(tt.resource); got != tt.want {
				t.Fatalf("fetchProtocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNetworkPolicyMatcher(t *testing.T) {
	tests := []struct {
		name           string
		policyResource string
		action         string
		resource       string
		result         string
		wantPolicy     string
		wantAction     string
	}{
		{
			name:           "blocks matching address family",
			policyResource: "af_rds",
			action:         "Block",
			resource:       "domain=AF_RDS",
			result:         "Permission denied",
			wantPolicy:     "ksp-network-policy",
			wantAction:     "Block",
		},
		{
			name:           "does not match another address family",
			policyResource: "af_rds",
			action:         "Block",
			resource:       "domain=AF_INET",
			result:         "Permission denied",
		},
		{
			name:           "keeps existing protocol block matching",
			policyResource: "tcp",
			action:         "Block",
			resource:       "protocol=TCP type=SOCK_STREAM",
			result:         "Permission denied",
			wantPolicy:     "ksp-network-policy",
			wantAction:     "Block",
		},
		{
			name:           "keeps socket type block matching",
			policyResource: "raw",
			action:         "Block",
			resource:       "type=SOCK_RAW protocol=HOPOPT",
			result:         "Permission denied",
			wantPolicy:     "ksp-network-policy",
			wantAction:     "Block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd := newNetworkPolicyFeeder(tt.policyResource, tt.action)
			out := fd.UpdateMatchedPolicy(networkLog(tt.resource, tt.result))

			if out.PolicyName != tt.wantPolicy {
				t.Fatalf("PolicyName = %q, want %q", out.PolicyName, tt.wantPolicy)
			}
			if out.Action != tt.wantAction {
				t.Fatalf("Action = %q, want %q", out.Action, tt.wantAction)
			}
		})
	}
}

func TestHostNetworkPolicyMatcherUsesActiveNode(t *testing.T) {
	originalHost := cfg.GlobalCfg.Host
	cfg.GlobalCfg.Host = "configured-host"
	t.Cleanup(func() { cfg.GlobalCfg.Host = originalHost })

	fd := &Feeder{
		BaseFeeder: BaseFeeder{
			Node: &tp.Node{
				NodeName:                 "active-node",
				NetworkVisibilityEnabled: true,
			},
			Enforcer:     "BPFLSM",
			EnforcerLock: new(sync.RWMutex),
		},
		SecurityPolicies:     map[string]tp.MatchPolicies{},
		SecurityPoliciesLock: new(sync.RWMutex),
		DefaultPostures:      map[string]tp.DefaultPosture{},
		DefaultPosturesLock:  new(sync.Mutex),
	}
	fd.UpdateHostSecurityPolicies("UPDATED", []tp.HostSecurityPolicy{
		{
			Metadata: map[string]string{"policyName": "hsp-block-net-af-rds"},
			Spec: tp.HostSecuritySpec{
				Network: tp.NetworkType{
					MatchProtocols: []tp.NetworkProtocolType{{
						Protocol: "AF_RDS",
						Action:   "Block",
					}},
				},
			},
		},
	})

	out := fd.UpdateMatchedPolicy(tp.Log{
		Operation:     "Network",
		Resource:      "domain=AF_RDS type=SOCK_SEQPACKET protocol=HOPOPT",
		Result:        "Permission denied",
		PolicyEnabled: tp.KubeArmorPolicyEnabled,
	})

	if out.Type != "MatchedHostPolicy" {
		t.Fatalf("Type = %q, want MatchedHostPolicy", out.Type)
	}
	if out.PolicyName != "hsp-block-net-af-rds" {
		t.Fatalf("PolicyName = %q, want hsp-block-net-af-rds", out.PolicyName)
	}
	if out.Action != "Block" {
		t.Fatalf("Action = %q, want Block", out.Action)
	}
}
