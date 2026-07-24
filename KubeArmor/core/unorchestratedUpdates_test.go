// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUniqueEndpointNamespaces(t *testing.T) {
	t.Parallel()

	endpoints := []tp.EndPoint{
		{NamespaceName: "team-b", EndPointName: "ep-1"},
		{NamespaceName: "team-a", EndPointName: "ep-2"},
		{NamespaceName: "team-b", EndPointName: "ep-3"},
		{NamespaceName: "team-c", EndPointName: "ep-4"},
		{NamespaceName: "team-a", EndPointName: "ep-5"},
	}

	namespaces := uniqueEndpointNamespaces(endpoints)
	expected := []string{"team-a", "team-b", "team-c"}

	if len(namespaces) != len(expected) {
		t.Fatalf("expected %d namespaces, got %d (%v)", len(expected), len(namespaces), namespaces)
	}

	for idx, namespace := range expected {
		if namespaces[idx] != namespace {
			t.Fatalf("expected namespaces %v, got %v", expected, namespaces)
		}
	}
}
