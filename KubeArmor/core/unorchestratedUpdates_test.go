// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"regexp"
	"sync"
	"testing"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParseAndUpdateContainerSecurityPolicy_Regex(t *testing.T) {
	node := tp.Node{}
	nodeLock := &sync.RWMutex{}
	logger := fd.NewFeeder(&node, &nodeLock)

	dm := &KubeArmorDaemon{
		EndPoints:            []tp.EndPoint{},
		EndPointsLock:        &sync.RWMutex{},
		SecurityPolicies:     []tp.SecurityPolicy{},
		SecurityPoliciesLock: &sync.RWMutex{},
		Containers:           map[string]tp.Container{},
		ContainersLock:       &sync.RWMutex{},
		Logger:               logger,
	}

	// 1. Valid regex patterns
	validPolicyEvent := tp.K8sKubeArmorPolicyEvent{
		Type: "ADDED",
		Object: tp.K8sKubeArmorPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "valid-regex-policy",
			},
			Spec: tp.SecuritySpec{
				Selector: tp.SelectorType{
					MatchLabels: map[string]string{
						"kubearmor.io/container.name": "container-[0-9]+",
						"custom-label":                "^val-[a-z]+$",
					},
				},
			},
		},
	}

	status := dm.ParseAndUpdateContainerSecurityPolicy(validPolicyEvent)
	if status != pb.PolicyStatus_Applied {
		t.Fatalf("expected PolicyStatus_Applied, got %v", status)
	}

	if len(dm.EndPoints) != 1 {
		t.Fatalf("expected 1 endpoint to be created, got %d", len(dm.EndPoints))
	}

	ep := dm.EndPoints[0]
	if ep.IdentitiesRegexp == nil {
		t.Fatal("expected ep.IdentitiesRegexp to be initialized")
	}

	rxContainer, ok := ep.IdentitiesRegexp["kubearmor.io/container.name"]
	if !ok || rxContainer == nil {
		t.Fatal("expected compiled regex for kubearmor.io/container.name")
	}

	if !rxContainer.MatchString("container-123") {
		t.Error("expected container-[0-9]+ to match container-123")
	}

	if rxContainer.MatchString("container-abc") {
		t.Error("expected container-[0-9]+ to NOT match container-abc")
	}

	rxCustom, ok := ep.IdentitiesRegexp["custom-label"]
	if !ok || rxCustom == nil {
		t.Fatal("expected compiled regex for custom-label")
	}

	if !rxCustom.MatchString("val-xyz") {
		t.Error("expected ^val-[a-z]+$ to match val-xyz")
	}

	if rxCustom.MatchString("val-123") {
		t.Error("expected ^val-[a-z]+$ to NOT match val-123")
	}

	// 2. Invalid regex pattern
	invalidPolicyEvent := tp.K8sKubeArmorPolicyEvent{
		Type: "ADDED",
		Object: tp.K8sKubeArmorPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "invalid-regex-policy",
			},
			Spec: tp.SecuritySpec{
				Selector: tp.SelectorType{
					MatchLabels: map[string]string{
						"kubearmor.io/container.name": "container-[0-9",
					},
				},
			},
		},
	}

	status = dm.ParseAndUpdateContainerSecurityPolicy(invalidPolicyEvent)
	if status != pb.PolicyStatus_Invalid {
		t.Fatalf("expected PolicyStatus_Invalid, got %v", status)
	}
}

func TestMatchIdentities_Regex(t *testing.T) {
	dm := &KubeArmorDaemon{}

	// Setup compiled regexes
	rx1 := regexp.MustCompile("prod-.*")
	rx2 := regexp.MustCompile("^web-[0-9]+$")

	ep := tp.EndPoint{
		Identities: []string{
			"namespaceName=container_namespace",
			"env=prod-.*",
			"app=^web-[0-9]+$",
		},
		IdentitiesRegexp: map[string]*regexp.Regexp{
			"env": rx1,
			"app": rx2,
		},
	}

	// Case 1: Match succeeds
	labels1 := map[string]string{
		"namespaceName": "container_namespace",
		"env":           "prod-service",
		"app":           "web-42",
	}
	if !dm.MatchIdentities(ep, labels1) {
		t.Error("expected MatchIdentities to return true for matching labels")
	}

	// Case 2: Match fails due to mismatched regex (app)
	labels2 := map[string]string{
		"namespaceName": "container_namespace",
		"env":           "prod-service",
		"app":           "web-abc",
	}
	if dm.MatchIdentities(ep, labels2) {
		t.Error("expected MatchIdentities to return false due to app value mismatch")
	}

	// Case 3: Match fails due to missing label (env)
	labels3 := map[string]string{
		"namespaceName": "container_namespace",
		"app":           "web-42",
	}
	if dm.MatchIdentities(ep, labels3) {
		t.Error("expected MatchIdentities to return false due to missing env label")
	}

	// Case 4: Match fails due to mismatched namespaceName
	labels4 := map[string]string{
		"namespaceName": "different_namespace",
		"env":           "prod-service",
		"app":           "web-42",
	}
	if dm.MatchIdentities(ep, labels4) {
		t.Error("expected MatchIdentities to return false due to namespaceName mismatch")
	}
}
