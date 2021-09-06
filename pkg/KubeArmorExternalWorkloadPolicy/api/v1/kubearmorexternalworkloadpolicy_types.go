// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:singular="kubearmorexternalworkload",path="kubearmorexternalworkloads",scope="Cluster",shortName={kew}
// +kubebuilder:subresource:status
type KubeArmorExternalWorkloadPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired configuration of the external KubeArmor workload.
	Spec KubeArmorExternalWorkloadPolicySpec `json:"spec,omitempty"`

	// Status is the most recent status of the external KubeArmor workload.
	// It is a read-only field.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status KubeArmorExternalWorkloadPolicyStatus `json:"status"`
}

// KubeArmorExternalWorkloadPolicySpec specifies the configurations for redirecting traffic
// within a workload.
//
// +kubebuilder:validation:Type=object
type KubeArmorExternalWorkloadPolicySpec struct {
	// IPv4AllocCIDR is the range of IPv4 addresses in the CIDR format that the external workload can
	// use to allocate IP addresses for the tunnel device and the health endpoint.
	//
	// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$`
	IPv4AllocCIDR string `json:"ipv4-alloc-cidr,omitempty"`

	// IPv6AllocCIDR is the range of IPv6 addresses in the CIDR format that the external workload can
	// use to allocate IP addresses for the tunnel device and the health endpoint.
	//
	// +kubebuilder:validation:Pattern=`^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`
	IPv6AllocCIDR string `json:"ipv6-alloc-cidr,omitempty"`
}

// KubeArmorExternalWorkloadPolicyStatus is the status of a the external KubeArmor workload.
type KubeArmorExternalWorkloadPolicyStatus struct {
	// ID is the numeric identity allocated for the external workload.
	ID uint64 `json:"id,omitempty"`

	// IP is the IP address of the workload. Empty if the workload has not registered.
	IP string `json:"ip,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false

// KubeArmorExternalWorkloadPolicyList is a list of KubeArmorExternalWorkloadPolicy objects.
type KubeArmorExternalWorkloadPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of KubeArmorExternalWorkloadPolicy
	Items []KubeArmorExternalWorkloadPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorExternalWorkloadPolicy{}, &KubeArmorExternalWorkloadPolicyList{})
}
