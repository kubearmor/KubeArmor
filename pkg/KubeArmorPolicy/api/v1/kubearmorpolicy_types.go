// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:Minimum:=1
// +kubebuilder:validation:Maximum:=10
type SeverityType int

type SelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// +kubebuilder:validation:Pattern=^\/([A-z0-9-_.]+\/)*([A-z0-9-_.]+)$
type MatchPathType string

// +kubebuilder:validation:Pattern=^\/([A-z0-9-_.]+\/)*([A-z0-9-_.]+)+\/$
type MatchDirectoryType string

type MatchSourceType struct {
	Path      MatchPathType      `json:"path,omitempty"`
	Directory MatchDirectoryType `json:"dir,omitempty"`

	// +kubebuilder:validation:Optional
	Recursive bool `json:"recursive,omitempty"`
}

type ProcessPathType struct {
	Path MatchPathType `json:"path"`

	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessDirectoryType struct {
	Directory MatchDirectoryType `json:"dir"`

	// +kubebuilder:validation:Optional
	Recursive bool `json:"recursive,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessPatternType struct {
	Pattern string `json:"pattern"`

	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessType struct {
	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FilePathType struct {
	Path MatchPathType `json:"path"`

	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FileDirectoryType struct {
	Directory MatchDirectoryType `json:"dir"`

	// +kubebuilder:validation:Optional
	Recursive bool `json:"recursive,omitempty"`
	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FilePatternType struct {
	Pattern string `json:"pattern"`

	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FileType struct {
	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Pattern=(icmp|ICMP|tcp|TCP|udp|UDP)$
type MatchNetworkProtocolStringType string

type MatchNetworkProtocolType struct {
	Protocol MatchNetworkProtocolStringType `json:"protocol"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type NetworkType struct {
	MatchProtocols []MatchNetworkProtocolType `json:"matchProtocols"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Pattern=(net_raw)$
type MatchCapabilitiesStringType string

type MatchCapabilitiesType struct {
	Capability MatchCapabilitiesStringType `json:"capability"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type CapabilitiesType struct {
	MatchCapabilities []MatchCapabilitiesType `json:"matchCapabilities"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Enum=Allow;Audit;Block
type ActionType string

// KubeArmorPolicySpec defines the desired state of KubeArmorPolicy
type KubeArmorPolicySpec struct {
	Selector SelectorType `json:"selector"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`

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
// +kubebuilder:resource:shortName=ksp
// +kubebuilder:subresource:status
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
