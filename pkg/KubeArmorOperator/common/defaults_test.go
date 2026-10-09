// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import "testing"

func TestGetOCIHooks(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "operator", value: "yes", expected: true},
		{name: "snitch", value: "true", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBEARMOR_OCI_HOOKS", tt.value)

			if got := GetOCIHooks(); got != tt.expected {
				t.Errorf("GetOCIHooks() = %v, want %v", got, tt.expected)
			}
		})
	}
}
