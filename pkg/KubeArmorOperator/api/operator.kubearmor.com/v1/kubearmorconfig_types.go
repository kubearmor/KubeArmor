// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

// +kubebuilder:validation:optional
package v1

import (
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ImageSpec defines the image specifications
type ImageSpec struct {
	Args []string `json:"args,omitempty"`

	Image string `json:"image,omitempty"`

	// +kubebuilder:validation:Enum=Always;IfNotPresent;Never
	// +kubebuilder:default:=Always
	ImagePullPolicy string `json:"imagePullPolicy,omitempty"`

	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
}

type Tls struct {

	// +kubebuilder:default:=false
	Enable bool `json:"enable,omitempty"`

	RelayExtraDnsNames []string `json:"extraDnsNames,omitempty"`

	RelayExtraIpAddresses []string `json:"extraIpAddresses,omitempty"`
}

type RecommendedPolicies struct {
	Enable bool `json:"enable,omitempty"`

	MatchExpressions []securityv1.MatchExpressionsType `json:"matchExpressions,omitempty"`

	ExcludePolicy []string `json:"excludePolicy,omitempty"`
}

type ElasticSearchAuth struct {
	SecretName       string `json:"secretName,omitempty"`
	UserNameKey      string `json:"usernameKey,omitempty"`
	PasswordKey      string `json:"passwordKey,omitempty"`
	AllowTlsInsecure bool   `json:"allowInsecureTLS,omitempty"`
	CAcertSecretName string `json:"caCertSecretName,omitempty"`
	CaCertKey        string `json:"caCertKey,omitempty"`
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

	RecommendedPolicies RecommendedPolicies `json:"recommendedPolicies,omitempty"`

	DefaultFilePosture PostureType `json:"defaultFilePosture,omitempty"`

	DefaultCapabilitiesPosture PostureType `json:"defaultCapabilitiesPosture,omitempty"`

	DefaultNetworkPosture PostureType `json:"defaultNetworkPosture,omitempty"`

	DefaultVisibility string `json:"defaultVisibility,omitempty"`

	GloabalImagePullSecrets []corev1.LocalObjectReference `json:"globalImagePullSecrets,omitempty"`

	GlobalTolerations []corev1.Toleration `json:"globalTolerations,omitempty"`

	KubeArmorImage ImageSpec `json:"kubearmorImage,omitempty"`

	KubeArmorInitImage ImageSpec `json:"kubearmorInitImage,omitempty"`

	KubeArmorRelayImage ImageSpec `json:"kubearmorRelayImage,omitempty"`

	KubeArmorControllerImage ImageSpec `json:"kubearmorControllerImage,omitempty"`

	// +kubebuilder:deprecatedversion:warning="kube-rbac-proxy has been deprecated with controller authz"
	// Deprecated: This type would be removed in one of the upcoming releases.
	KubeRbacProxyImage ImageSpec `json:"kubeRbacProxyImage,omitempty"`

	Tls Tls `json:"tls,omitempty"`

	EnableStdOutLogs bool `json:"enableStdOutLogs,omitempty"`

	EnableStdOutAlerts bool `json:"enableStdOutAlerts,omitempty"`

	EnableStdOutMsgs bool `json:"enableStdOutMsgs,omitempty"`

	SeccompEnabled bool `json:"seccompEnabled,omitempty"`

	AlertThrottling bool `json:"alertThrottling,omitempty"`

	MaxAlertPerSec int `json:"maxAlertPerSec,omitempty"`

	ThrottleSec int `json:"throttleSec,omitempty"`

	Adapters Adapters `json:"adapters,omitempty"`

	EnableNRI bool `json:"enableNRI,omitempty"`

	DropResourceFromProcessLogs bool `json:"dropResourceFromProcessLogs,omitempty"`

	ControllerPort int `json:"controllerPort,omitempty"`
}

// KubeArmorConfigStatus defines the observed state of KubeArmorConfig
type KubeArmorConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Phase string `json:"phase,omitempty"`

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
