// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KubeArmorHostPolicySpec defines the desired state of KubeArmorHostPolicy
type KubeArmorHostPolicySpec struct {
	NodeSelector NodeSelectorType `json:"nodeSelector"`

	Process      ProcessType          `json:"process,omitempty"`
	File         FileType             `json:"file,omitempty"`
	Network      HostNetworkType      `json:"network,omitempty"`
	Capabilities HostCapabilitiesType `json:"capabilities,omitempty"`
	Syscalls     SyscallsType         `json:"syscalls,omitempty"`

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

// KubeArmorHostPolicyStatus defines the observed state of KubeArmorHostPolicy
type KubeArmorHostPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorHostPolicy is the Schema for the kubearmorhostpolicies API
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster,shortName=hsp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`,priority=10
// +kubebuilder:printcolumn:name="Selector",type=string,JSONPath=`.spec.nodeSelector.matchLabels`,priority=10
type KubeArmorHostPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorHostPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorHostPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorHostPolicyList contains a list of KubeArmorHostPolicy
type KubeArmorHostPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorHostPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorHostPolicy{}, &KubeArmorHostPolicyList{})
}
