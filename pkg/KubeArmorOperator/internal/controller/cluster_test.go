// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"testing"

	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
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

func TestUpdateTlsData(t *testing.T) {
	origEnable, origDns, origIps := common.EnableTls, common.ExtraDnsNames, common.ExtraIpAddresses
	t.Cleanup(func() {
		common.EnableTls, common.ExtraDnsNames, common.ExtraIpAddresses = origEnable, origDns, origIps
	})

	common.EnableTls = false
	common.ExtraDnsNames = []string{"localhost"}
	common.ExtraIpAddresses = []string{"127.0.0.1"}

	updated := UpdateTlsData(&opv1.KubeArmorConfigSpec{
		Tls: opv1.Tls{
			Enable:                true,
			RelayExtraDnsNames:    []string{"relay.example.com"},
			RelayExtraIpAddresses: []string{"10.0.0.10"},
		},
	})
	assert.True(t, updated)
	assert.True(t, common.EnableTls)
	assert.Equal(t, []string{"relay.example.com"}, common.ExtraDnsNames)
	assert.Equal(t, []string{"10.0.0.10"}, common.ExtraIpAddresses)

	// only IP addresses set: DNS names must be left untouched
	updated = UpdateTlsData(&opv1.KubeArmorConfigSpec{
		Tls: opv1.Tls{
			Enable:                true,
			RelayExtraIpAddresses: []string{"10.0.0.11"},
		},
	})
	assert.False(t, updated)
	assert.Equal(t, []string{"relay.example.com"}, common.ExtraDnsNames)
	assert.Equal(t, []string{"10.0.0.11"}, common.ExtraIpAddresses)
}
