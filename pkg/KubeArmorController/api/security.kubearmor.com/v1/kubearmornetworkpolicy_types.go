// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KubeArmorNetworkPolicySpec defines the desired state of KubeArmorNetworkPolicy
type KubeArmorNetworkPolicySpec struct {
	NodeSelector NodeSelectorType `json:"nodeSelector"`

	Ingress []IngressType `json:"ingress,omitempty"`
	Egress  []EgressType  `json:"egress,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// KubeArmorNetworkPolicyStatus defines the observed state of KubeArmorNetworkPolicy
type KubeArmorNetworkPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorNetworkPolicy is the Schema for the kubearmornetworkpolicies API
// +genclient
// +genclient:nonNamespaced
// +kubebuilder:resource:scope=Cluster,shortName=nsp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`,priority=10
// +kubebuilder:printcolumn:name="Selector",type=string,JSONPath=`.spec.nodeSelector.matchLabels`,priority=10
type KubeArmorNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorNetworkPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorNetworkPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KubeArmorNetworkPolicyList contains a list of KubeArmorNetworkPolicy
type KubeArmorNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorNetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorNetworkPolicy{}, &KubeArmorNetworkPolicyList{})
}
