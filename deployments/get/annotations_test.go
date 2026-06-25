// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package deployments

import "testing"

func TestApplyInfraPodPolicyAnnotations(t *testing.T) {
	tests := []struct {
		name    string
		input   map[string]string
		enabled bool
		want    map[string]string
	}{
		{
			name:    "disabled defaults to audited",
			enabled: false,
			want: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyAuditedValue,
			},
		},
		{
			name:    "enabled sets self-protection and policy",
			enabled: true,
			want: map[string]string{
				SelfProtectionAnnotation:  SelfProtectionEnabledValue,
				KubeArmorPolicyAnnotation:   KubeArmorPolicyEnabledValue,
			},
		},
		{
			name: "enabled preserves disabled policy",
			input: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
			enabled: true,
			want: map[string]string{
				SelfProtectionAnnotation:  SelfProtectionEnabledValue,
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
		},
		{
			name: "disabled preserves disabled policy",
			input: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
			enabled: false,
			want: map[string]string{
				KubeArmorPolicyAnnotation: KubeArmorPolicyDisabledValue,
			},
		},
		{
			name: "enabled merges with existing annotations",
			input: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/manager": "unconfined",
			},
			enabled: true,
			want: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/manager": "unconfined",
				SelfProtectionAnnotation:                                   SelfProtectionEnabledValue,
				KubeArmorPolicyAnnotation:                                  KubeArmorPolicyEnabledValue,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyInfraPodPolicyAnnotations(copyMap(tt.input), tt.enabled)
			for key, wantVal := range tt.want {
				if got[key] != wantVal {
					t.Fatalf("annotation %q = %q, want %q (full map: %#v)", key, got[key], wantVal, got)
				}
			}
		})
	}
}

func copyMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}

	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}

	return out
}
