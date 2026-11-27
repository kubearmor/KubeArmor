// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
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

func TestUpdateResourceRequirementsIfDefinedAndUpdated(t *testing.T) {
	t.Run("both empty - no update", func(t *testing.T) {
		commonRes := corev1.ResourceRequirements{}
		inRes := corev1.ResourceRequirements{}

		updated := UpdateResourceRequirementsIfDefinedAndUpdated(&commonRes, inRes)
		assert.False(t, updated)
		assert.Equal(t, corev1.ResourceRequirements{}, commonRes)
	})

	t.Run("new resources defined - update applied", func(t *testing.T) {
		commonRes := corev1.ResourceRequirements{}
		inRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("200Mi"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("50Mi"),
			},
		}

		updated := UpdateResourceRequirementsIfDefinedAndUpdated(&commonRes, inRes)
		assert.True(t, updated)
		assert.Equal(t, inRes, commonRes)
	})

	t.Run("identical resources - no update", func(t *testing.T) {
		commonRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("200Mi"),
			},
		}
		inRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("200Mi"),
			},
		}

		updated := UpdateResourceRequirementsIfDefinedAndUpdated(&commonRes, inRes)
		assert.False(t, updated)
	})

	t.Run("modified resources - update applied", func(t *testing.T) {
		commonRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("200Mi"),
			},
		}
		inRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		}

		updated := UpdateResourceRequirementsIfDefinedAndUpdated(&commonRes, inRes)
		assert.True(t, updated)
		assert.Equal(t, inRes, commonRes)
	})

	t.Run("resources removed - reset to empty", func(t *testing.T) {
		commonRes := corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("200Mi"),
			},
		}
		inRes := corev1.ResourceRequirements{}

		updated := UpdateResourceRequirementsIfDefinedAndUpdated(&commonRes, inRes)
		assert.True(t, updated)
		assert.Equal(t, corev1.ResourceRequirements{}, commonRes)
	})
}

func TestUpdateImagesWithImageAndResources(t *testing.T) {
	origImage := common.KubeArmorImage
	origRes := common.KubeArmorResources
	t.Cleanup(func() {
		common.KubeArmorImage = origImage
		common.KubeArmorResources = origRes
	})

	common.KubeArmorImage = "kubearmor/kubearmor:v1.0.0"
	common.KubeArmorResources = corev1.ResourceRequirements{}

	expectedRes := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
	}

	cfg := &opv1.KubeArmorConfigSpec{
		KubeArmorImage: opv1.ImageSpec{
			Image:     "kubearmor/kubearmor:v2.0.0",
			Resources: expectedRes,
		},
	}

	updated := UpdateImages(cfg)

	assert.Contains(t, updated, "kubearmor")
	assert.Equal(t, "kubearmor/kubearmor:v2.0.0", common.KubeArmorImage)
	assert.Equal(t, expectedRes, common.KubeArmorResources)
}
