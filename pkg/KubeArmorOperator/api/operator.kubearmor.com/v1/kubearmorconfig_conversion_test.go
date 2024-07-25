// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

import (
	"testing"

	operatorv2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	v1Config = KubeArmorConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: "kubearmorconfig-test",
		},
		Spec: KubeArmorConfigSpec{
			DefaultFilePosture:         PostureType("audit"),
			DefaultCapabilitiesPosture: PostureType("audit"),
			DefaultNetworkPosture:      PostureType("audit"),
			DefaultVisibility:          "process,network",
			EnableStdOutLogs:           false,
			EnableStdOutAlerts:         false,
			EnableStdOutMsgs:           false,
			SeccompEnabled:             false,
			AlertThrottling:            false,
			MaxAlertPerSec:             10,
			ThrottleSec:                30,
			KubeArmorImage: ImageSpec{
				Image:           "kubearmor/kubearmor:stable",
				ImagePullPolicy: "Always",
			},
			KubeArmorInitImage: ImageSpec{
				Image:           "kubearmor/kubearmor-init:stable",
				ImagePullPolicy: "Always",
			},
			KubeArmorRelayImage: ImageSpec{
				Image:           "kubearmor/kubearmor-relay-server",
				ImagePullPolicy: "Always",
			},
			KubeArmorControllerImage: ImageSpec{
				Image:           "kubearmor/kubearmor-controller",
				ImagePullPolicy: "Always",
			},
		},
	}

	v2Config = operatorv2.KubeArmorConfig{
		ObjectMeta: v1.ObjectMeta{
			Name: "kubearmorconfig-test",
		},
		Spec: operatorv2.KubeArmorConfigSpec{
			KubeArmorConfigMap: operatorv2.KubeArmorConfigMapSpec{
				DefaultFilePosture:         operatorv2.DefaultPosture("audit"),
				DefaultCapabilitiesPosture: operatorv2.DefaultPosture("audit"),
				DefaultNetworkPosture:      operatorv2.DefaultPosture("audit"),
				Visibility:                 "process,network",
				AlertThrottling:            false,
				MaxAlertPerSec:             10,
				ThrottleSec:                30,
			},
			KubeArmor: operatorv2.KubeArmorSpec{
				Image: operatorv2.Image{
					Registry:   "kubearmor",
					Repository: "kubearmor",
					Tag:        "stable",
				},
				ImagePullPolicy: "Always",
			},
			KubeArmorInit: operatorv2.KubeArmorInitSpec{
				Image: operatorv2.Image{
					Registry:   "kubearmor",
					Repository: "kubearmor-init",
					Tag:        "stable",
				},
				ImagePullPolicy: "Always",
			},
			KubeArmorRelay: operatorv2.KubeArmorRelaySpec{
				Image: operatorv2.Image{
					Registry:   "kubearmor",
					Repository: "kubearmor-relay-server",
					Tag:        "",
				},
				ImagePullPolicy:    "Always",
				EnableStdOutLogs:   "false",
				EnableStdOutAlerts: "false",
				EnableStdOutMsg:    "false",
			},
			KubeArmorController: operatorv2.KubeArmorControllerSpec{
				Image: operatorv2.Image{
					Registry:   "kubearmor",
					Repository: "kubearmor-controller",
					Tag:        "",
				},
				ImagePullPolicy: "Always",
			},
		},
	}
)

func TestConversionFromV1ToV2(t *testing.T) {
	testv2 := &operatorv2.KubeArmorConfig{}
	err := v1Config.ConvertTo(testv2)
	assert.Nil(t, err)
	assert.Equal(t, v2Config, *testv2)
}

func TestConversionFromV2toV1(t *testing.T) {
	testv1 := &KubeArmorConfig{}
	err := testv1.ConvertFrom(&v2Config)
	assert.Nil(t, err)
	assert.Equal(t, v1Config, *testv1)
}
