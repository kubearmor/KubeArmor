// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type EventType struct {
	Probe string `json:"probe"`
	Rate  string `json:"rate,omitempty"`

	// file related arguments

	// +kubebuilder:validation:Optional
	Path string `json:"path,omitempty"`
	// +kubebuilder:validation:Optional
	Directory string `json:"dir,omitempty"`
	// +kubebuilder:validation:Optional
	Mode string `json:"mode,omitempty"`
	// +kubebuilder:validation:Optional
	Flags string `json:"flags,omitempty"`

	// socket related arguments

	// +kubebuilder:validation:Enum=ip;tcp;udp;raw;IP;TCP;UDP;RAW
	Protocol string `json:"protocol,omitempty"`
	// +kubebuilder:validation:Optional
	Ipv4Addr string `json:"ipv4addr,omitempty"`
	// +kubebuilder:validation:Optional
	Ipv6Addr string `json:"ipv6addr,omitempty"`
	// +kubebuilder:validation:Optional
	Port string `json:"port,omitempty"`
}

// +kubebuilder:validation:Pattern=^([1-9]|10)$
type SeverityType string

type AuditRuleType struct {
	// +kubebuilder:validation:Default="*"
	Process string `json:"process,omitempty"`

	Events []EventType `json:"events"`

	// +kubebuilder:validation:Optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`
}

type SelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// KubeArmorAuditPolicySpec defines the desired state of KubeArmorAuditPolicy
type KubeArmorAuditPolicySpec struct {
	Selector   SelectorType    `json:"selector"`
	AuditRules []AuditRuleType `json:"rules"`

	// +kubebuilder:validation:Optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`
}

// KubeArmorAuditPolicyStatus defines the observed state of KubeArmorAuditPolicy
type KubeArmorAuditPolicyStatus struct {
	AuditPolicyStatus string `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KubeArmorAuditPolicy is the Schema for the kubearmorauditpolicies API
type KubeArmorAuditPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorAuditPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorAuditPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubeArmorAuditPolicyList contains a list of KubeArmorAuditPolicy
type KubeArmorAuditPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorAuditPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorAuditPolicy{}, &KubeArmorAuditPolicyList{})
}
