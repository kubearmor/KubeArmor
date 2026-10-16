// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestUpdateEnvIfDefinedAndUpdated(t *testing.T) {
	commonEnv := []corev1.EnvVar{}

	// new env should be updated
	UpdateEnvIfDefinedAndUpdated(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
	})
	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1", commonEnv[0].Value)

	// duplicate entry should not be updated
	UpdateEnvIfDefinedAndUpdated(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
		{
			Name:  "env1",
			Value: "val1",
		},
	})

	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1", commonEnv[0].Value)

	// add multiple env vars
	UpdateEnvIfDefinedAndUpdated(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
		{
			Name:  "env2",
			Value: "val2",
		},
	})

	assert.Equal(t, 2, len(commonEnv))
	assert.Equal(t, "env2", commonEnv[1].Name)
	assert.Equal(t, "val2", commonEnv[1].Value)

	// element should be marked removed
	UpdateEnvIfDefinedAndUpdated(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
	})

	assert.Equal(t, 2, len(commonEnv))
	assert.Equal(t, "env2", commonEnv[1].Name)
	assert.Equal(t, "-", commonEnv[1].Value)

	// env value should be updated
	UpdateEnvIfDefinedAndUpdated(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env2",
			Value: "val2",
		},
	})

	assert.Equal(t, 2, len(commonEnv))
	assert.Equal(t, "env2", commonEnv[1].Name)
	assert.Equal(t, "val2", commonEnv[1].Value)
}

func TestAddorUpdateEnv(t *testing.T) {
	commonEnv := []corev1.EnvVar{}

	// new env should be updated
	AddOrUpdateEnv(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
	})
	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1", commonEnv[0].Value)

	// duplicate entry should not be updated
	AddOrUpdateEnv(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
		{
			Name:  "env1",
			Value: "val1",
		},
	})

	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1", commonEnv[0].Value)

	// add multiple env vars
	AddOrUpdateEnv(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
		{
			Name:  "env2",
			Value: "val2",
		},
	})

	assert.Equal(t, 2, len(commonEnv))
	assert.Equal(t, "env2", commonEnv[1].Name)
	assert.Equal(t, "val2", commonEnv[1].Value)

	// element marked as removed should not be added
	AddOrUpdateEnv(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1",
		},
		{
			Name:  "env2",
			Value: "-",
		},
	})

	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1", commonEnv[0].Value)

	// env value should be updated
	AddOrUpdateEnv(&commonEnv, []corev1.EnvVar{
		{
			Name:  "env1",
			Value: "val1-updated",
		},
	})

	assert.Equal(t, 1, len(commonEnv))
	assert.Equal(t, "env1", commonEnv[0].Name)
	assert.Equal(t, "val1-updated", commonEnv[0].Value)

	t.Run("no panic on nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expected no panic but got when executed with nil")
			}
		}()

		AddOrUpdateEnv(nil, []corev1.EnvVar{
			{
				Name:  "env",
				Value: "val",
			},
		})
	})
}

func TestAddorUpdateNodeSelector(t *testing.T) {
	t.Run("no panic on nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Expected no panic but got when executed with nil")
			}
		}()

		AddOrUpdateNodeSelector(nil, map[string]string{
			"env": "test",
		})
	})
}

func TestNodeMatchesGlobalNodeSelector(t *testing.T) {
	tests := []struct {
		name                string
		nodeLabels          map[string]string
		globalSelectors     map[string]string
		expected            bool
	}{
		{
			name:            "empty global selectors matches any node",
			nodeLabels:      map[string]string{"key1": "value1"},
			globalSelectors: map[string]string{},
			expected:        true,
		},
		{
			name:            "single matching label",
			nodeLabels:      map[string]string{"env": "prod"},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        true,
		},
		{
			name:            "single non-matching label",
			nodeLabels:      map[string]string{"env": "dev"},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        false,
		},
		{
			name:            "multiple matching labels",
			nodeLabels:      map[string]string{"env": "prod", "zone": "us-east"},
			globalSelectors: map[string]string{"env": "prod", "zone": "us-east"},
			expected:        true,
		},
		{
			name:            "missing key in node labels",
			nodeLabels:      map[string]string{"env": "prod"},
			globalSelectors: map[string]string{"env": "prod", "zone": "us-east"},
			expected:        false,
		},
		{
			name:            "extra node labels should not affect",
			nodeLabels:      map[string]string{"env": "prod", "zone": "us-east", "extra": "x"},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        true,
		},
		{
			name:            "ignore deletion marker",
			nodeLabels:      map[string]string{"env": "prod", "zone": "us-east"},
			globalSelectors: map[string]string{"env": "prod", "zone": "-"},
			expected:        true,
		},
		{
			name:            "all deletion markers",
			nodeLabels:      map[string]string{"env": "prod"},
			globalSelectors: map[string]string{"env": "-", "zone": "-"},
			expected:        true,
		},
		{
			name:            "empty node labels with constraints",
			nodeLabels:      map[string]string{},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        false,
		},
		{
			name:            "both empty",
			nodeLabels:      map[string]string{},
			globalSelectors: map[string]string{},
			expected:        true,
		},
		{
			name:            "case sensitive key mismatch",
			nodeLabels:      map[string]string{"ENV": "prod"},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        false,
		},
		{
			name:            "case sensitive value mismatch",
			nodeLabels:      map[string]string{"env": "Prod"},
			globalSelectors: map[string]string{"env": "prod"},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := common.GlobalNodeSelectors
			defer func() {
				common.GlobalNodeSelectors = original
			}()

			common.GlobalNodeSelectors = tt.globalSelectors

			result := nodeMatchesGlobalNodeSelector(tt.nodeLabels)
			assert.Equal(t, tt.expected, result)
		})
	}
}