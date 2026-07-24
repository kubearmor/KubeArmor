// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controllers

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestPodForRecreateClearsServerPopulatedFields(t *testing.T) {
	deletionTime := metav1.NewTime(time.Now())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "standalone",
			Namespace:         "default",
			UID:               types.UID("server-uid"),
			ResourceVersion:   "12345",
			Generation:        2,
			CreationTimestamp: metav1.NewTime(time.Now()),
			DeletionTimestamp: &deletionTime,
			ManagedFields: []metav1.ManagedFieldsEntry{
				{Manager: "kube-apiserver"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}

	recreated := podForRecreate(pod)

	if recreated.UID != "" {
		t.Fatalf("expected UID to be cleared, got %q", recreated.UID)
	}
	if recreated.ResourceVersion != "" {
		t.Fatalf("expected resource version to be cleared, got %q", recreated.ResourceVersion)
	}
	if recreated.Generation != 0 {
		t.Fatalf("expected generation to be cleared, got %d", recreated.Generation)
	}
	if !recreated.CreationTimestamp.IsZero() {
		t.Fatalf("expected creation timestamp to be cleared, got %s", recreated.CreationTimestamp)
	}
	if recreated.DeletionTimestamp != nil {
		t.Fatalf("expected deletion timestamp to be cleared, got %s", recreated.DeletionTimestamp)
	}
	if len(recreated.ManagedFields) != 0 {
		t.Fatalf("expected managed fields to be cleared, got %v", recreated.ManagedFields)
	}
	if recreated.Status.Phase != "" {
		t.Fatalf("expected status to be cleared, got %q", recreated.Status.Phase)
	}
}

func TestPodForRecreatePreservesUserSettableFields(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:         "standalone",
			GenerateName: "standalone-",
			Namespace:    "default",
			Labels: map[string]string{
				"app": "demo",
			},
			Annotations: map[string]string{
				"kubearmor-policy": "enabled",
			},
			Finalizers: []string{"example.com/finalizer"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "nginx:latest",
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	recreated := podForRecreate(pod)

	if recreated.Name != pod.Name {
		t.Fatalf("expected name %q, got %q", pod.Name, recreated.Name)
	}
	if recreated.GenerateName != pod.GenerateName {
		t.Fatalf("expected generate name %q, got %q", pod.GenerateName, recreated.GenerateName)
	}
	if recreated.Namespace != pod.Namespace {
		t.Fatalf("expected namespace %q, got %q", pod.Namespace, recreated.Namespace)
	}
	if recreated.Labels["app"] != "demo" {
		t.Fatalf("expected labels to be preserved, got %v", recreated.Labels)
	}
	if recreated.Annotations["kubearmor-policy"] != "enabled" {
		t.Fatalf("expected annotations to be preserved, got %v", recreated.Annotations)
	}
	if len(recreated.Finalizers) != 1 || recreated.Finalizers[0] != "example.com/finalizer" {
		t.Fatalf("expected finalizers to be preserved, got %v", recreated.Finalizers)
	}
	if len(recreated.Spec.Containers) != 1 || recreated.Spec.Containers[0].Name != "app" {
		t.Fatalf("expected pod spec to be preserved, got %v", recreated.Spec)
	}

	pod.Labels["app"] = "changed"
	pod.Annotations["kubearmor-policy"] = "changed"
	pod.Finalizers[0] = "changed"
	pod.Spec.Containers[0].Name = "changed"

	if recreated.Labels["app"] != "demo" {
		t.Fatalf("expected labels to be copied, got %v", recreated.Labels)
	}
	if recreated.Annotations["kubearmor-policy"] != "enabled" {
		t.Fatalf("expected annotations to be copied, got %v", recreated.Annotations)
	}
	if recreated.Finalizers[0] != "example.com/finalizer" {
		t.Fatalf("expected finalizers to be copied, got %v", recreated.Finalizers)
	}
	if recreated.Spec.Containers[0].Name != "app" {
		t.Fatalf("expected pod spec to be copied, got %v", recreated.Spec.Containers)
	}
}
