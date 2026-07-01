package feeder

import (
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func newAFRDSFeeder(policyResource string) *Feeder {
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
				PolicyName:   "ksp-ubuntu-1-block-net-af-rds",
				Severity:     "8",
				Operation:    "Network",
				ResourceType: "Protocol",
				Resource:     policyResource,
				Action:       "Block",
			},
		},
	}
	return fd
}

func afrdsLog(resource string) tp.Log {
	return tp.Log{
		NamespaceName: "default",
		PodName:       "test-pod",
		Operation:     "Network",
		Resource:      resource,
		Result:        "Permission denied",
		PolicyEnabled: tp.KubeArmorPolicyEnabled,
	}
}

func TestAFRDSHelperExtraction(t *testing.T) {
	got := fetchAddressFamily("domain=AF_RDS type=SOCK_SEQPACKET protocol=0")
	if got != "af_rds" {
		t.Fatalf("fetchAddressFamily = %q, want af_rds", got)
	}
	if fetchAddressFamily("protocol=TCP type=SOCK_STREAM") != "" {
		t.Fatalf("fetchAddressFamily should be empty when no domain token present")
	}
}

func TestAFRDSBlockProducesAlert(t *testing.T) {
	fd := newAFRDSFeeder("af_rds")
	out := fd.UpdateMatchedPolicy(afrdsLog("domain=AF_RDS type=SOCK_SEQPACKET protocol=0"))

	if out.PolicyName != "ksp-ubuntu-1-block-net-af-rds" {
		t.Fatalf("PolicyName = %q, want ksp-ubuntu-1-block-net-af-rds", out.PolicyName)
	}
	if out.Action != "Block" {
		t.Fatalf("Action = %q, want Block", out.Action)
	}
}

// Negative control: an AF_RDS policy must NOT match an AF_INET socket.
func TestAFRDSDoesNotMatchOtherFamily(t *testing.T) {
	fd := newAFRDSFeeder("af_rds")
	out := fd.UpdateMatchedPolicy(afrdsLog("domain=AF_INET type=SOCK_STREAM protocol=TCP"))

	if out.PolicyName == "ksp-ubuntu-1-block-net-af-rds" {
		t.Fatalf("AF_RDS policy incorrectly matched an AF_INET socket")
	}
}
