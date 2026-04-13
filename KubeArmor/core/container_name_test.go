// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import "testing"

func TestResolveContainerName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		runtime string
		labels  map[string]string
		want    string
	}{
		{
			name:    "uses kubernetes container label when present",
			runtime: "/k8s_POD_backend-67f6d7c4b7-5x9df_default_12345_0",
			labels: map[string]string{
				kubernetesContainerNameLabel: "backend",
			},
			want: "backend",
		},
		{
			name:    "falls back to trimmed runtime name",
			runtime: "/k8s_POD_backend-67f6d7c4b7-5x9df_default_12345_0",
			want:    "k8s_POD_backend-67f6d7c4b7-5x9df_default_12345_0",
		},
		{
			name:    "keeps runtime name when it has no leading slash",
			runtime: "containerd://abcd1234",
			want:    "containerd://abcd1234",
		},
		{
			name:    "ignores empty kubernetes container label",
			runtime: "/container-123",
			labels: map[string]string{
				kubernetesContainerNameLabel: "",
			},
			want: "container-123",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := resolveContainerName(tt.runtime, tt.labels)
			if got != tt.want {
				t.Fatalf("resolveContainerName() = %q, want %q", got, tt.want)
			}
		})
	}
}
