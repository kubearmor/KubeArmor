// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newPolicyCacheTestDaemon() *KubeArmorDaemon {
	return &KubeArmorDaemon{
		NodeLock:                    &sync.RWMutex{},
		SecurityPolicies:            []tp.SecurityPolicy{},
		SecurityPoliciesLock:        &sync.RWMutex{},
		HostSecurityPolicies:        []tp.HostSecurityPolicy{},
		HostSecurityPoliciesLock:    &sync.RWMutex{},
		NetworkSecurityPolicies:     []tp.NetworkSecurityPolicy{},
		NetworkSecurityPoliciesLock: &sync.RWMutex{},
	}
}

func hostPolicyEvent(eventType, name, action string) tp.K8sKubeArmorHostPolicyEvent {
	return tp.K8sKubeArmorHostPolicyEvent{
		Type: eventType,
		Object: tp.K8sKubeArmorHostPolicy{
			Metadata: metav1.ObjectMeta{Name: name},
			Spec:     tp.HostSecuritySpec{Action: action},
		},
	}
}

func networkPolicyEvent(eventType, name, action string) tp.K8sKubeArmorNetworkPolicyEvent {
	return tp.K8sKubeArmorNetworkPolicyEvent{
		Type: eventType,
		Object: tp.K8sKubeArmorNetworkPolicy{
			Metadata: metav1.ObjectMeta{Name: name},
			Spec:     tp.NetworkSecuritySpec{Action: action},
		},
	}
}

func TestParseAndUpdateHostSecurityPolicyCachesUnknownModifiedPolicy(t *testing.T) {
	dm := newPolicyCacheTestDaemon()

	if status := dm.ParseAndUpdateHostSecurityPolicy(hostPolicyEvent(updateEvent, "hsp-missed-add", "Audit")); status != pb.PolicyStatus_Modified {
		t.Fatalf("expected status Modified, got %v", status)
	}
	if len(dm.HostSecurityPolicies) != 1 || dm.HostSecurityPolicies[0].Metadata["policyName"] != "hsp-missed-add" {
		t.Fatalf("expected the modified policy to be cached, got %+v", dm.HostSecurityPolicies)
	}

	// a second update replaces the cached copy instead of adding another one
	dm.ParseAndUpdateHostSecurityPolicy(hostPolicyEvent(updateEvent, "hsp-missed-add", "Block"))
	if len(dm.HostSecurityPolicies) != 1 {
		t.Fatalf("expected one cached policy, got %d", len(dm.HostSecurityPolicies))
	}
	if got := dm.HostSecurityPolicies[0].Spec.Action; got != "Block" {
		t.Fatalf("expected cached action Block, got %q", got)
	}
}

func TestParseAndUpdateNetworkSecurityPolicyCachesUnknownModifiedPolicy(t *testing.T) {
	dm := newPolicyCacheTestDaemon()

	if status := dm.ParseAndUpdateNetworkSecurityPolicy(networkPolicyEvent(updateEvent, "knp-missed-add", "Audit")); status != pb.PolicyStatus_Modified {
		t.Fatalf("expected status Modified, got %v", status)
	}
	if len(dm.NetworkSecurityPolicies) != 1 || dm.NetworkSecurityPolicies[0].Metadata["policyName"] != "knp-missed-add" {
		t.Fatalf("expected the modified policy to be cached, got %+v", dm.NetworkSecurityPolicies)
	}

	dm.ParseAndUpdateNetworkSecurityPolicy(networkPolicyEvent(updateEvent, "knp-missed-add", "Block"))
	if len(dm.NetworkSecurityPolicies) != 1 {
		t.Fatalf("expected one cached policy, got %d", len(dm.NetworkSecurityPolicies))
	}
	if got := dm.NetworkSecurityPolicies[0].Spec.Action; got != "Block" {
		t.Fatalf("expected cached action Block, got %q", got)
	}
}

func TestUpsertSecurityPolicy(t *testing.T) {
	policy := func(namespace, name, action string) tp.SecurityPolicy {
		return tp.SecurityPolicy{
			Metadata: map[string]string{"namespaceName": namespace, "policyName": name},
			Spec:     tp.SecuritySpec{Action: action},
		}
	}

	dm := newPolicyCacheTestDaemon()

	// a modified namespaced policy that was never cached is added
	dm.upsertSecurityPolicy(policy("ns-a", "ksp", "Audit"), false)
	if len(dm.SecurityPolicies) != 1 {
		t.Fatalf("expected one cached policy, got %d", len(dm.SecurityPolicies))
	}

	// the same name in another namespace is a different policy
	dm.upsertSecurityPolicy(policy("ns-b", "ksp", "Audit"), false)
	if len(dm.SecurityPolicies) != 2 {
		t.Fatalf("expected two cached policies, got %d", len(dm.SecurityPolicies))
	}

	// an update to a cached policy replaces it in place
	dm.upsertSecurityPolicy(policy("ns-a", "ksp", "Block"), false)
	if len(dm.SecurityPolicies) != 2 || dm.SecurityPolicies[0].Spec.Action != "Block" || dm.SecurityPolicies[1].Spec.Action != "Audit" {
		t.Fatalf("expected ns-a/ksp to be replaced in place, got %+v", dm.SecurityPolicies)
	}

	// cluster policies are matched by name only
	dm = newPolicyCacheTestDaemon()
	dm.upsertSecurityPolicy(policy("", "kcsp", "Audit"), true)
	dm.upsertSecurityPolicy(policy("", "kcsp", "Block"), true)
	if len(dm.SecurityPolicies) != 1 || dm.SecurityPolicies[0].Spec.Action != "Block" {
		t.Fatalf("expected one cluster policy with action Block, got %+v", dm.SecurityPolicies)
	}
}

func TestUpsertHostSecurityPolicy(t *testing.T) {
	policy := func(name, action string) tp.HostSecurityPolicy {
		return tp.HostSecurityPolicy{
			Metadata: map[string]string{"policyName": name},
			Spec:     tp.HostSecuritySpec{Action: action},
		}
	}

	dm := newPolicyCacheTestDaemon()

	dm.upsertHostSecurityPolicy(policy("hsp", "Audit"))
	if len(dm.HostSecurityPolicies) != 1 {
		t.Fatalf("expected one cached policy, got %d", len(dm.HostSecurityPolicies))
	}

	dm.upsertHostSecurityPolicy(policy("hsp", "Block"))
	if len(dm.HostSecurityPolicies) != 1 || dm.HostSecurityPolicies[0].Spec.Action != "Block" {
		t.Fatalf("expected the cached policy to be replaced, got %+v", dm.HostSecurityPolicies)
	}
}
