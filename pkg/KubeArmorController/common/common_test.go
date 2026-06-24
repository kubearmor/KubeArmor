// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddCommonAnnotationsKubeArmorInfra(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		annotations map[string]string
		wantPolicy  string
	}{
		{
			name:       "kubearmor-app without annotations defaults to audited",
			labels:     map[string]string{KubeArmorAppLabel: "kubearmor"},
			wantPolicy: KubeArmorPolicyAuditedValue,
		},
		{
			name:        "kubearmor-app with enabled but no self-protection stays audited",
			labels:      map[string]string{KubeArmorAppLabel: "kubearmor"},
			annotations: map[string]string{KubeArmorPolicyAnnotation: KubeArmorPolicyEnabledValue},
			wantPolicy:  KubeArmorPolicyAuditedValue,
		},
		{
			name: "kubearmor-app with disabled stays disabled",
			labels: map[string]string{
				KubeArmorAppLabel: "kubearmor",
			},
			annotations: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
			wantPolicy: KubeArmorPolicyDisabledValue,
		},
		{
			name: "kubearmor-app with audited stays audited",
			labels: map[string]string{
				KubeArmorAppLabel: "kubearmor",
			},
			annotations: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyAuditedValue,
			},
			wantPolicy: KubeArmorPolicyAuditedValue,
		},
		{
			name: "self-protection opt-in enables enforcement",
			labels: map[string]string{
				KubeArmorAppLabel: "kubearmor",
			},
			annotations: map[string]string{
				SelfProtectionAnnotation: SelfProtectionEnabledValue,
			},
			wantPolicy: KubeArmorPolicyEnabledValue,
		},
		{
			name: "self-protection opt-in with disabled preserves disabled",
			labels: map[string]string{
				KubeArmorAppLabel: "kubearmor",
			},
			annotations: map[string]string{
				SelfProtectionAnnotation:  SelfProtectionEnabledValue,
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
			wantPolicy: KubeArmorPolicyDisabledValue,
		},
		{
			name: "self-protection opt-in overrides audited template",
			labels: map[string]string{
				KubeArmorAppLabel: "kubearmor",
			},
			annotations: map[string]string{
				SelfProtectionAnnotation:  SelfProtectionEnabledValue,
				KubeArmorPolicyAnnotation: KubeArmorPolicyAuditedValue,
			},
			wantPolicy: KubeArmorPolicyEnabledValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{
				Namespace:   "kubearmor",
				Labels:      tt.labels,
				Annotations: copyStringMap(tt.annotations),
			}

			AddCommonAnnotations(obj)

			if got := obj.Annotations[KubeArmorPolicyAnnotation]; got != tt.wantPolicy {
				t.Fatalf("kubearmor-policy = %q, want %q", got, tt.wantPolicy)
			}
		})
	}
}

func TestAddCommonAnnotationsNonInfraDefaults(t *testing.T) {
	obj := &metav1.ObjectMeta{
		Namespace: "default",
		Labels: map[string]string{
			"app": "nginx",
		},
	}

	AddCommonAnnotations(obj)

	if got := obj.Annotations[KubeArmorPolicyAnnotation]; got != KubeArmorPolicyEnabledValue {
		t.Fatalf("kubearmor-policy = %q, want %q", got, KubeArmorPolicyEnabledValue)
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}

	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}

	return out
}
