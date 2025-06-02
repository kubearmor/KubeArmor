// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type MatchExpressionsType struct {
	// +kubebuilder:validation:Enum=label
	Key string `json:"key,omitempty"`

	// +kubebuilder:validation:Enum=In;NotIn
	Operator string `json:"operator,omitempty"`

	Values []string `json:"values,omitempty"`
}

type SelectorType struct {
	MatchLabels      map[string]string      `json:"matchLabels,omitempty"`
	MatchExpressions []MatchExpressionsType `json:"matchExpressions,omitempty"`
}

type MatchVolumeMountType struct {
	// +kubebuilder:validation:Optional
	Path MatchPathType `json:"path,omitempty"`
	// +kubebuilder:validation:Optional
	Directory MatchDirectoryType `json:"dir,omitempty"`
	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type SELinuxType struct {
	MatchVolumeMounts []MatchVolumeMountType `json:"matchVolumeMounts"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// KubeArmorPolicySpec defines the desired state of KubeArmorPolicy
type KubeArmorPolicySpec struct {
	Selector SelectorType `json:"selector,omitempty"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`
	Syscalls     SyscallsType     `json:"syscalls,omitempty"`
	Presets      []PresetType     `json:"presets,omitempty"`

	AppArmor string `json:"apparmor,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// KubeArmorPolicyStatus defines the observed state of KubeArmorPolicy
type KubeArmorPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorPolicy is the Schema for the kubearmorpolicies API
// +genclient
// +kubebuilder:resource:shortName=ksp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`,priority=10
// +kubebuilder:printcolumn:name="Selector",type=string,JSONPath=`.spec.selector.matchLabels`,priority=10
type KubeArmorPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorPolicyList contains a list of KubeArmorPolicy
type KubeArmorPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorPolicy{}, &KubeArmorPolicyList{})
}
