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

// +kubebuilder:validation:Pattern=^([1-9]|10)$
type SeverityType string

type EventType struct {
	Syscall string `json:"syscall,omitempty"`
	Kprobe  string `json:"kprobe,omitempty"`

	// +kubebuilder:validation:Pattern=^([0-9]+p[0-9]+s|[0-9]+p[0-9]+m)$
	Rate string `json:"rate,omitempty"`

	// socket related arguments
	// +kubebuilder:validation:Enum=ip;tcp;udp;raw;IP;TCP;UDP;RAW
	Protocol string `json:"protocol,omitempty"`
	// +kubebuilder:validation:Optional
	Port string `json:"port,omitempty"`
	// +kubebuilder:validation:Optional
	Ipv4Addr string `json:"ipv4addr,omitempty"`
	// +kubebuilder:validation:Optional
	Ipv6Addr string `json:"ipv6addr,omitempty"`

	// file related arguments
	// +kubebuilder:validation:Pattern=^\/([A-z0-9-_.]+\/)*([A-z0-9-_.]+)$
	Path string `json:"path,omitempty"`
	// +kubebuilder:validation:Optional
	Mode string `json:"mode,omitempty"`
	// 	+kubebuilder:validation:Pattern=^/([A-z0-9-.]+/)*([A-z0-9-.]+)+/$
	Directory string `json:"dir,omitempty"`
}

type AuditRuleType struct {
	// +kubebuilder:validation:Default="*"
	Process string `json:"process,omitempty"`

	// +kubebuilder:validation:Optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`

	Events []EventType `json:"events"`
}

// KubeArmorAuditPolicySpec defines the desired state of KubeArmorAuditPolicy
type KubeArmorAuditPolicySpec struct {
	// +kubebuilder:validation:Optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:Optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`

	AuditRules []AuditRuleType `json:"rules"`
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
