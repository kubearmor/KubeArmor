package handlers

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestCountMatchingPods(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name          string
		namespace     string
		labels        map[string]string
		pods          []corev1.Pod
		expectedCount int
	}{
		{
			name:      "no pods in cluster",
			namespace: "default",
			labels:    map[string]string{"app": "test"},
			pods:      []corev1.Pod{},
			expectedCount: 0,
		},
		{
			name:      "pods match selector",
			namespace: "default",
			labels:    map[string]string{"app": "test"},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Labels:    map[string]string{"app": "test"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod2",
						Namespace: "default",
						Labels:    map[string]string{"app": "test"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name:      "pods dont match selector",
			namespace: "default",
			labels:    map[string]string{"app": "test"},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Labels:    map[string]string{"app": "other"},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name:      "pods in different namespace",
			namespace: "default",
			labels:    map[string]string{"app": "test"},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "other-namespace",
						Labels:    map[string]string{"app": "test"},
					},
				},
			},
			expectedCount: 0,
		},
		{
			name:      "partial label match",
			namespace: "default",
			labels:    map[string]string{"app": "test", "env": "prod"},
			pods: []corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "default",
						Labels:    map[string]string{"app": "test"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]runtime.Object, len(tt.pods))
			for i := range tt.pods {
				objs[i] = &tt.pods[i]
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				Build()

			validator := &PolicyValidator{
				Client: fakeClient,
				Logger: logr.New(log.NullLogSink{}),
			}

			count, err := validator.countMatchingPods(context.Background(), tt.namespace, tt.labels)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if count != tt.expectedCount {
				t.Errorf("expected %d pods, got %d", tt.expectedCount, count)
			}
		})
	}
}

func TestCountMatchingNodes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name          string
		labels        map[string]string
		nodes         []corev1.Node
		expectedCount int
	}{
		{
			name:          "no nodes in cluster",
			labels:        map[string]string{"kubernetes.io/os": "linux"},
			nodes:         []corev1.Node{},
			expectedCount: 0,
		},
		{
			name:   "nodes match selector",
			labels: map[string]string{"kubernetes.io/os": "linux"},
			nodes: []corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node2",
						Labels: map[string]string{"kubernetes.io/os": "linux"},
					},
				},
			},
			expectedCount: 2,
		},
		{
			name:   "nodes dont match selector",
			labels: map[string]string{"kubernetes.io/os": "linux"},
			nodes: []corev1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "node1",
						Labels: map[string]string{"kubernetes.io/os": "windows"},
					},
				},
			},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]runtime.Object, len(tt.nodes))
			for i := range tt.nodes {
				objs[i] = &tt.nodes[i]
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				Build()

			validator := &HostPolicyValidator{
				Client: fakeClient,
				Logger: logr.New(log.NullLogSink{}),
			}

			count, err := validator.countMatchingNodes(context.Background(), tt.labels)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if count != tt.expectedCount {
				t.Errorf("expected %d nodes, got %d", tt.expectedCount, count)
			}
		})
	}
}

func TestValidateKubeArmorPolicyWithPodMatching(t *testing.T) {
	result := securityv1.ValidateKubeArmorPolicy(&securityv1.KubeArmorPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: securityv1.KubeArmorPolicySpec{
			Selector: securityv1.SelectorType{
				MatchLabels: map[string]string{"app": "test"},
			},
			Process: securityv1.ProcessType{
				MatchPaths: []securityv1.ProcessPathType{
					{Path: "/usr/bin/bash"},
				},
			},
		},
	})

	if result.HasErrors() {
		t.Errorf("expected no errors for valid policy, got: %s", result.ErrorMessages())
	}
}
