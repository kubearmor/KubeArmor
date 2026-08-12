// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controllers

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
)

func TestRestartResourcesCanonicalKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		kind      string
		resource  string
		clientset *fake.Clientset
		verify    func(context.Context, *testing.T, *fake.Clientset)
	}{
		{
			name:     "deployment",
			kind:     "Deployment",
			resource: "deploy",
			clientset: fake.NewSimpleClientset(&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "deploy", Namespace: "default"},
				Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{}},
			}),
			verify: func(ctx context.Context, t *testing.T, clientset *fake.Clientset) {
				t.Helper()
				deployment, err := clientset.AppsV1().Deployments("default").Get(ctx, "deploy", metav1.GetOptions{})
				if err != nil {
					t.Fatalf("get deployment: %v", err)
				}
				assertRestartAnnotation(t, deployment.Spec.Template.Annotations)
			},
		},
		{
			name:     "statefulset",
			kind:     "StatefulSet",
			resource: "stateful",
			clientset: fake.NewSimpleClientset(&appsv1.StatefulSet{
				ObjectMeta: metav1.ObjectMeta{Name: "stateful", Namespace: "default"},
				Spec:       appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{}},
			}),
			verify: func(ctx context.Context, t *testing.T, clientset *fake.Clientset) {
				t.Helper()
				statefulSet, err := clientset.AppsV1().StatefulSets("default").Get(ctx, "stateful", metav1.GetOptions{})
				if err != nil {
					t.Fatalf("get statefulset: %v", err)
				}
				assertRestartAnnotation(t, statefulSet.Spec.Template.Annotations)
			},
		},
		{
			name:     "daemonset",
			kind:     "DaemonSet",
			resource: "daemon",
			clientset: fake.NewSimpleClientset(&appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{Name: "daemon", Namespace: "default"},
				Spec:       appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{}},
			}),
			verify: func(ctx context.Context, t *testing.T, clientset *fake.Clientset) {
				t.Helper()
				daemonSet, err := clientset.AppsV1().DaemonSets("default").Get(ctx, "daemon", metav1.GetOptions{})
				if err != nil {
					t.Fatalf("get daemonset: %v", err)
				}
				assertRestartAnnotation(t, daemonSet.Spec.Template.Annotations)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := restartResources(map[string]ResourceInfo{
				tt.resource: {
					kind:          tt.kind,
					namespaceName: "default",
				},
			}, tt.clientset)
			if err != nil {
				t.Fatalf("restartResources returned error: %v", err)
			}

			tt.verify(context.Background(), t, tt.clientset)
		})
	}
}

func assertRestartAnnotation(t *testing.T, annotations map[string]string) {
	t.Helper()

	if annotations == nil {
		t.Fatal("expected restart annotation map to be initialized")
	}
	if annotations[common.KubeArmorRestartedAnnotation] == "" {
		t.Fatalf("expected %q annotation to be set", common.KubeArmorRestartedAnnotation)
	}
}
