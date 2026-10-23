// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddCommonAnnotationsVisibility(t *testing.T) {
	previous := SetDefaultVisibility("process,network")
	defer SetDefaultVisibility(previous)

	obj := &metav1.ObjectMeta{}
	AddCommonAnnotations(obj)
	if got := obj.Annotations[VisibilityAnnotation]; got != "process,network" {
		t.Errorf("expected configured default visibility, got %q", got)
	}

	obj = &metav1.ObjectMeta{Annotations: map[string]string{VisibilityAnnotation: "file"}}
	AddCommonAnnotations(obj)
	if got := obj.Annotations[VisibilityAnnotation]; got != "file" {
		t.Errorf("expected existing visibility to be kept, got %q", got)
	}
}
