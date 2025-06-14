// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ClusterMatchExpressionsType struct {
	// +kubebuilder:validation:Enum=namespace;label
	Key string `json:"key,omitempty"`

	// +kubebuilder:validation:Enum=In;NotIn
	Operator string `json:"operator,omitempty"`

	Values []string `json:"values,omitempty"`
}

type NsSelectorType struct {
	MatchExpressions []ClusterMatchExpressionsType `json:"matchExpressions,omitempty"`
}

// KubeArmorClusterPolicySpec defines the desired state of KubeArmorClusterPolicy
type KubeArmorClusterPolicySpec struct {
	Selector NsSelectorType `json:"selector,omitempty"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`
	Syscalls     SyscallsType     `json:"syscalls,omitempty"`

	AppArmor string       `json:"apparmor,omitempty"`
	Presets  []PresetType `json:"presets,omitempty"`
	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// KubeArmorClusterPolicyStatus defines the observed state of KubeArmorCLusterPolicy
type KubeArmorClusterPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorClusterPolicy is the Schema for the kubearmorclusterpolicies API
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:shortName=csp,scope="Cluster"
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`,priority=10
// +kubebuilder:printcolumn:name="Selector",type=string,JSONPath=`.spec.selector.matchExpressions`,priority=10
type KubeArmorClusterPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorClusterPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorClusterPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorClusterPolicyList contains a list of KubeArmorClusterPolicy
type KubeArmorClusterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorClusterPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorClusterPolicy{}, &KubeArmorClusterPolicyList{})
}
