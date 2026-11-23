// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
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

func TestDeploySnitchTolerations(t *testing.T) {
	// Preserve and restore the global tolerations so we don't leak state into other tests.
	saved := common.GlobalTolerations
	defer func() { common.GlobalTolerations = saved }()

	common.GlobalTolerations = []corev1.Toleration{
		{Operator: corev1.TolerationOpExists},
	}

	job := deploySnitch("test-node", "containerd")

	assert.Equal(t, common.GlobalTolerations, job.Spec.Template.Spec.Tolerations,
		"snitch Job should apply the configured globalTolerations so it can schedule onto tainted nodes")
}
