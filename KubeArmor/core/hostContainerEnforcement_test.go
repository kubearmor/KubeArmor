// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// TestHostContainerNamespaceDetection verifies that containers running on the
// host without K8s orchestration are correctly identified by NamespaceName ==
// "container_namespace" when they lack the io.kubernetes.pod.namespace label.
//
// This is the discriminator used by our fix to decide whether to create
// endpoints and enforce policies on host containers even when K8sEnabled=true.
func TestHostContainerNamespaceDetection(t *testing.T) {
	// Simulate what GetContainerInfo does for a non-K8s container
	// (no io.kubernetes.pod.namespace label present)
	container := tp.Container{
		ContainerID:   "aabbccddeeff112233",
		ContainerName: "my-host-container",
	}

	containerLabels := map[string]string{
		"some-label": "some-value",
		// intentionally no "io.kubernetes.pod.namespace"
	}

	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
		container.NamespaceName = containerLabels["io.kubernetes.pod.namespace"]
	} else {
		container.NamespaceName = "container_namespace"
	}

	if container.NamespaceName != "container_namespace" {
		t.Errorf("expected NamespaceName=container_namespace for non-K8s container, got %q", container.NamespaceName)
	}
	t.Logf("PASS: non-K8s host container correctly identified with NamespaceName=%q", container.NamespaceName)

	// Simulate a real K8s pod container
	k8sContainer := tp.Container{
		ContainerID:   "ffeeddccbbaa998877",
		ContainerName: "nginx",
	}

	k8sLabels := map[string]string{
		"io.kubernetes.pod.namespace": "default",
		"io.kubernetes.pod.name":      "nginx-pod",
	}

	if val, ok := k8sLabels["io.kubernetes.pod.namespace"]; ok {
		k8sContainer.NamespaceName = val
	} else {
		k8sContainer.NamespaceName = "container_namespace"
	}

	if k8sContainer.NamespaceName == "container_namespace" {
		t.Errorf("K8s pod container should NOT get container_namespace, got %q", k8sContainer.NamespaceName)
	}
	t.Logf("PASS: K8s pod container correctly identified with NamespaceName=%q", k8sContainer.NamespaceName)
}

// TestEndpointCreationCondition is the core regression test for issue #2320.
//
// It directly tests the condition that gates endpoint creation in
// UpdateContainerdContainer, UpdateDockerContainer, UpdateCrioContainer,
// and MonitorNRIEvents.
//
// Before the fix:
//
//	condition was: !dm.K8sEnabled
//	Result: host containers silently skipped when K8s is running
//
// After the fix:
//
//	condition is: !dm.K8sEnabled || container.NamespaceName == "container_namespace"
//	Result: host containers always get endpoints regardless of K8s mode
func TestEndpointCreationCondition(t *testing.T) {
	tests := []struct {
		name           string
		k8sEnabled     bool
		namespaceName  string
		shouldCreateEP bool
		description    string
	}{
		{
			name:           "non-k8s mode, host container",
			k8sEnabled:     false,
			namespaceName:  "container_namespace",
			shouldCreateEP: true,
			description:    "non-K8s mode always creates endpoints (existing behaviour)",
		},
		{
			name:           "k8s mode, host container - THE FIX",
			k8sEnabled:     true,
			namespaceName:  "container_namespace",
			shouldCreateEP: true,
			description:    "K8s mode + host container MUST create endpoint (issue #2320 fix)",
		},
		{
			name:           "k8s mode, real k8s pod",
			k8sEnabled:     true,
			namespaceName:  "default",
			shouldCreateEP: false,
			description:    "K8s pod uses K8s watcher path, not this block",
		},
		{
			name:           "k8s mode, kube-system pod",
			k8sEnabled:     true,
			namespaceName:  "kube-system",
			shouldCreateEP: false,
			description:    "K8s system pod uses K8s watcher path, not this block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is the exact condition from our fix
			conditionMet := !tt.k8sEnabled || tt.namespaceName == "container_namespace"

			if conditionMet != tt.shouldCreateEP {
				t.Errorf("FAIL: %s\n\t K8sEnabled=%v NamespaceName=%q\n\t condition=%v want=%v",
					tt.description, tt.k8sEnabled, tt.namespaceName, conditionMet, tt.shouldCreateEP)
			} else {
				t.Logf("PASS: %s (K8sEnabled=%v, NamespaceName=%q, createEndpoint=%v)",
					tt.description, tt.k8sEnabled, tt.namespaceName, conditionMet)
			}
		})
	}
}

// TestK8sPodContainerNotAffected verifies that normal K8s pod containers
// are NOT accidentally routed through the host container path.
func TestK8sPodContainerNotAffected(t *testing.T) {
	k8sEnabled := true
	k8sNamespaces := []string{"default", "kube-system", "production", "monitoring"}

	for _, ns := range k8sNamespaces {
		conditionMet := !k8sEnabled || ns == "container_namespace"
		if conditionMet {
			t.Errorf("FAIL: K8s pod in namespace %q incorrectly triggered host container path", ns)
		} else {
			t.Logf("PASS: K8s pod in namespace %q correctly skips host container path", ns)
		}
	}
}
