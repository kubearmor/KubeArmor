// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// +kubebuilder:validation:Optional
package v2

import (
	corev1 "k8s.io/api/core/v1"
)

// +kubebuilder:validation:Enum:=Always;IfNotPresent;Never
type ImagePullPolicy string

type TLS struct {
	Enabled bool `json:"enabled,omitempty"`
}

type Image struct {
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type ImagePullSecrets struct {
	Name string `json:"name,omitempty"`
}

type TLSConfig struct {
	ExtraDNSNames    []string `json:"extraDNSNames,omitempty"`
	ExtraIPAddresses []string `json:"extraIPAddresses,omitempty"`
}

type KubeArmorRelaySpec struct {
	// +kubebuilder:default:=true
	Enable            bool                `json:"enable,omitempty"`
	Image             Image               `json:"image,omitempty"`
	ImagePullPolicy   ImagePullPolicy     `json:"imagePullPolicy,omitempty"`
	ImagePullSecrets  []ImagePullSecrets  `json:"imagePullSecrets,omitempty"`
	Args              []string            `json:"args,omitempty"`
	Tolerations       []corev1.Toleration `json:"tolerations,omitempty"`
	PriorityClassName string              `json:"priorityClassName,omitempty"`
	// +kubebuilder:validation:Enum:="true";"false"
	EnableStdOutLogs string `json:"enableStdOutLogs,omitempty"`
	// +kubebuilder:validation:Enum:="true";"false"
	EnableStdOutAlerts string `json:"enableStdOutAlerts,omitempty"`
	// +kubebuilder:validation:Enum:="true";"false"
	EnableStdOutMsg string `json:"enableStdOutMsg,omitempty"`

	TLS TLSConfig `json:"tls,omitempty"`
}

type KubeArmorSpec struct {
	Image             Image               `json:"image,omitempty"`
	ImagePullPolicy   ImagePullPolicy     `json:"imagePullPolicy,omitempty"`
	ImagePullSecrets  []ImagePullSecrets  `json:"imagePullSecrets,omitempty"`
	Args              []string            `json:"args,omitempty"`
	Tolerations       []corev1.Toleration `json:"tolerations,omitempty"`
	PriorityClassName string              `json:"priorityClassName,omitempty"`
}

type KubeArmorInitSpec struct {
	Deploy          bool            `json:"deploy,omitempty"`
	Image           Image           `json:"image,omitempty"`
	ImagePullPolicy ImagePullPolicy `json:"imagePullPolicy,omitempty"`
	Args            []string        `json:"args,omitempty"`
}

type KubeRbacProxySpec struct {
	Image           Image           `json:"image,omitempty"`
	ImagePullPolicy ImagePullPolicy `json:"imagePullPolicy,omitempty"`
	Args            []string        `json:"args,omitempty"`
}

type Mutation struct {
	// +kubebuilder:validation:Enum:=Ignore;Fail
	FailurePolicy string `json:"failurePolicy,omitempty"`
}

type KubeArmorControllerSpec struct {
	Image             Image               `json:"image,omitempty"`
	ImagePullPolicy   ImagePullPolicy     `json:"imagePullPolicy,omitempty"`
	ImagePullSecrets  []ImagePullSecrets  `json:"imagePullSecrets,omitempty"`
	Mutation          Mutation            `json:"mutation,omitempty"`
	Args              []string            `json:"args,omitempty"`
	Tolerations       []corev1.Toleration `json:"tolerations,omitempty"`
	PriorityClassName string              `json:"priorityClassName,omitempty"`
}

// +kubebuilder:validation:Enum:=audit;block
type DefaultPosture string

type KubeArmorConfigMapSpec struct {
	DefaultFilePosture         DefaultPosture `json:"defaultFilePosture,omitempty"`
	DefaultCapabilitiesPosture DefaultPosture `json:"defaultCapabilitiesPosture,omitempty"`
	DefaultNetworkPosture      DefaultPosture `json:"defaultNetworkPosture,omitempty"`
	Visibility                 string         `json:"visibility,omitempty"`
	AlertThrottling            bool           `json:"alertThrottling,omitempty"`
	MaxAlertPerSec             int            `json:"maxAlertPerSec,omitempty"`
	ThrottleSec                int            `json:"throttleSec,omitempty"`
}
