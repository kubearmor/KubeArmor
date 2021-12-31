/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

// +kubebuilder:validation:Enum=Allow;Audit;Block
type ActionType string

// +kubebuilder:validation:Enum=x86_64;x86;x32;arm;mips;mips64n32;mips64;mipsel;mipsel64n32;mipsel64;s390;s390x
type ArchType string

type SyscallType string

type SeccompType struct {
	// +kubebuilder:validation:optional
	Archs []ArchType `json:"arch,omitempty"`

	Syscalls []SyscallType `json:"syscalls,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// KubeArmorSeccompPolicySpec defines the desired state of KubeArmorSeccompPolicy
type KubeArmorSeccompPolicySpec struct {
	// Selector for pod selection
	Selector SelectorType `json:"selector"`

	// Seccomp Rules
	Seccomp SeccompType `json:"seccomp,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`

	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`

	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
}

// KubeArmorSeccompPolicyStatus defines the observed state of KubeArmorSeccompPolicy
type KubeArmorSeccompPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
// +kubebuilder:resource:shortName=kscmp
// KubeArmorSeccompPolicy is the Schema for the kubearmorseccomppolicies API
type KubeArmorSeccompPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorSeccompPolicySpec   `json:"spec,omitempty"`
	Status KubeArmorSeccompPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubeArmorSeccompPolicyList contains a list of KubeArmorSeccompPolicy
type KubeArmorSeccompPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorSeccompPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorSeccompPolicy{}, &KubeArmorSeccompPolicyList{})
}
