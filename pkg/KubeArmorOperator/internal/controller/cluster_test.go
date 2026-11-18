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

func TestRemoveDeletedEntriesForNodeSelector(t *testing.T) {
	ns := map[string]string{
		"keep":    "val",
		"removed": "-",
	}

	RemoveDeletedEntriesForNodeSelector(ns)

	assert.Equal(t, map[string]string{"keep": "val"}, ns)
}

func TestUpdateNodeSelectorIfDefinedAndUpdatedAfterRemoval(t *testing.T) {
	commonNS := map[string]string{}

	assert.True(t, UpdateNodeSelectorIfDefinedAndUpdated(commonNS, map[string]string{"a": "1", "b": "2"}))

	// removing "b" marks it as deleted so components drop it
	assert.True(t, UpdateNodeSelectorIfDefinedAndUpdated(commonNS, map[string]string{"a": "1"}))
	assert.Equal(t, "-", commonNS["b"])

	// once the deletion has been propagated the marker must be cleaned up,
	// otherwise every later reconcile reports a spurious change
	RemoveDeletedEntriesForNodeSelector(commonNS)
	assert.Equal(t, map[string]string{"a": "1"}, commonNS)
	assert.False(t, UpdateNodeSelectorIfDefinedAndUpdated(commonNS, map[string]string{"a": "1"}))
}
