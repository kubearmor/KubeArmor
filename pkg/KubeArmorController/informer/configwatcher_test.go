// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package informer

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestUpdatePodVisibility(t *testing.T) {
	pod := func(name, visibility string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   "default",
			Annotations: map[string]string{common.VisibilityAnnotation: visibility},
		}}
	}
	c := fake.NewClientset(
		pod("defaulted", "process,file,network,capabilities"),
		pod("custom", "file"),
	)

	updatePodVisibility(c, "process,file,network,capabilities", "process,network", logr.Discard())

	want := map[string]string{"defaulted": "process,network", "custom": "file"}
	for name, visibility := range want {
		p, err := c.CoreV1().Pods("default").Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Annotations[common.VisibilityAnnotation]; got != visibility {
			t.Errorf("pod %s: expected visibility %q, got %q", name, visibility, got)
		}
	}
}
