// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package v1

import (
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageSpec defines the image specifications
type ImageSpec struct {
	// +kubebuilder:validation:optional
	Image string `json:"image,omitempty"`
	// +kubebuilder:validation:optional
	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +kubebuilder:default:=Always
	ImagePullPolicy string `json:"imagePullPolicy,omitempty"`
}

type Tls struct {
	// +kubebuilder:validation:optional
	// +kubebuilder:default:=false
	Enable bool `json:"enable,omitempty"`
	// +kubebuilder:validation:optional
	RelayExtraDnsNames []string `json:"extraDnsNames,omitempty"`
	// +kubebuilder:validation:optional
	RelayExtraIpAddresses []string `json:"extraIpAddresses,omitempty"`
}

type RecommendedPolicies struct {
	Enable bool `json:"enable,omitempty"`

	MatchExpressions []securityv1.MatchExpressionsType `json:"matchExpressions,omitempty"`

	ExcludePolicy []string `json:"excludePolicy,omitempty"`
}

type ElasticSearchAuth struct {
	SecretName  string `json:"secretName,omitempty"`
	UserNameKey string `json:"usernameKey,omitempty"`
	PasswordKey string `json:"passwordKey,omitempty"`
}

type ElasticSearchAdapter struct {
	Enabled         bool              `json:"enabled,omitempty"`
	Url             string            `json:"url,omitempty"`
	AlertsIndexName string            `json:"alertsIndex,omitempty"`
	Auth            ElasticSearchAuth `json:"auth,omitempty"`
}

type Adapters struct {
	ElasticSearch ElasticSearchAdapter `json:"elasticsearch,omitempty"`
}

// KubeArmorConfigSpec defines the desired state of KubeArmorConfig
type KubeArmorConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:optional
	RecommendedPolicies RecommendedPolicies `json:"recommendedPolicies,omitempty"`
	// +kubebuilder:validation:optional
	DefaultFilePosture PostureType `json:"defaultFilePosture,omitempty"`
	// +kubebuilder:validation:optional
	DefaultCapabilitiesPosture PostureType `json:"defaultCapabilitiesPosture,omitempty"`
	// +kubebuilder:validation:optional
	DefaultNetworkPosture PostureType `json:"defaultNetworkPosture,omitempty"`
	// +kubebuilder:validation:optional
	DefaultVisibility string `json:"defaultVisibility,omitempty"`
	// +kubebuilder:validation:optional
	KubeArmorImage ImageSpec `json:"kubearmorImage,omitempty"`
	// +kubebuilder:validation:optional
	KubeArmorInitImage ImageSpec `json:"kubearmorInitImage,omitempty"`
	// +kubebuilder:validation:optional
	KubeArmorRelayImage ImageSpec `json:"kubearmorRelayImage,omitempty"`
	// +kubebuilder:validation:optional
	KubeArmorControllerImage ImageSpec `json:"kubearmorControllerImage,omitempty"`
	// +kubebuilder:validation:optional
	KubeRbacProxyImage ImageSpec `json:"kubeRbacProxyImage,omitempty"`
	// +kubebuilder:validation:optional
	Tls Tls `json:"tls,omitempty"`
	// +kubebuilder:validation:optional
	EnableStdOutLogs bool `json:"enableStdOutLogs,omitempty"`
	// +kubebuilder:validation:optional
	EnableStdOutAlerts bool `json:"enableStdOutAlerts,omitempty"`
	// +kubebuilder:validation:optional
	EnableStdOutMsgs bool `json:"enableStdOutMsgs,omitempty"`
	// +kubebuilder:validation:Optional
	SeccompEnabled bool `json:"seccompEnabled,omitempty"`
	// +kubebuilder:validation:Optional
	AlertThrottling bool `json:"alertThrottling,omitempty"`
	// +kubebuilder:validation:Optional
	MaxAlertPerSec int `json:"maxAlertPerSec,omitempty"`
	// +kubebuilder:validation:Optional
	ThrottleSec int `json:"throttleSec,omitempty"`
	// +kubebuilder:validation:Optional
	Adapters Adapters `json:"adapters,omitempty"`
}

// KubeArmorConfigStatus defines the observed state of KubeArmorConfig
type KubeArmorConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// +kubebuilder:validation:optional
	Phase string `json:"phase,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
// KubeArmorConfig is the Schema for the KubeArmorConfigs API
type KubeArmorConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorConfigSpec   `json:"spec,omitempty"`
	Status KubeArmorConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubeArmorConfigList contains a list of KubeArmorConfig
type KubeArmorConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorConfig{}, &KubeArmorConfigList{})
}
