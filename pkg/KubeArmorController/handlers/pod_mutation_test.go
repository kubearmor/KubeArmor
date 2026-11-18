// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestPodAnnotator_Handle_Binding_PodFetchFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	decoder := admission.NewDecoder(scheme)

	binding := &corev1.Binding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Target: corev1.ObjectReference{
			Name: "test-node",
		},
	}
	rawBinding, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("failed to marshal binding: %v", err)
	}

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Binding",
			},
			Namespace: "default",
			Name:      "test-pod",
			Object: runtime.RawExtension{
				Raw: rawBinding,
			},
		},
	}

	// Fake client without the pod so Get() fails with NotFound error
	fakeClientSet := fake.NewSimpleClientset()

	cluster := &types.Cluster{
		ClusterLock: &sync.RWMutex{},
		Nodes: map[string]*types.NodeInfo{
			"test-node": {
				KubeArmorActive: true,
			},
		},
	}

	annotator := &PodAnnotator{
		Decoder:   decoder,
		Logger:    logr.Discard(),
		Cluster:   cluster,
		ClientSet: fakeClientSet,
	}

	resp := annotator.Handle(context.Background(), req)

	if resp.Allowed {
		t.Errorf("expected response not to be allowed when pod fetch fails")
	}
	if resp.Result == nil || resp.Result.Code != http.StatusInternalServerError {
		t.Errorf("expected status code %d, got %v", http.StatusInternalServerError, resp.Result)
	}
}

func TestPodAnnotator_Handle_Binding_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	decoder := admission.NewDecoder(scheme)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/test-container": "localhost/kubearmor-test",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test-container"},
			},
		},
	}

	binding := &corev1.Binding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Target: corev1.ObjectReference{
			Name: "test-node",
		},
	}
	rawBinding, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("failed to marshal binding: %v", err)
	}

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Binding",
			},
			Namespace: "default",
			Name:      "test-pod",
			Object: runtime.RawExtension{
				Raw: rawBinding,
			},
		},
	}

	fakeClientSet := fake.NewSimpleClientset(pod)

	cluster := &types.Cluster{
		ClusterLock: &sync.RWMutex{},
		Nodes: map[string]*types.NodeInfo{
			"test-node": {
				KubeArmorActive: true,
			},
		},
	}

	annotator := &PodAnnotator{
		Decoder:   decoder,
		Logger:    logr.Discard(),
		Cluster:   cluster,
		ClientSet: fakeClientSet,
	}

	resp := annotator.Handle(context.Background(), req)

	if !resp.Allowed {
		t.Errorf("expected response to be allowed on success, got: %v", resp.Result)
	}
}
