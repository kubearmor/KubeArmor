// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// +kubebuilder:validation:Optional
package v2

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// Hub marks this type as a conversion hub.
func (*KubeArmorConfig) Hub() {}

// KubeArmorConfigSpec defines the desired state of KubeArmorConfig
type KubeArmorConfigSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	GlobalRegistry                   string                  `json:"globalRegistry,omitempty"`
	UseGlobalRegistryForVendorImages bool                    `json:"useGlobalRegistryForVendorImages,omitempty"`
	TLS                              TLS                     `json:"tls,omitempty"`
	KubeArmorRelay                   KubeArmorRelaySpec      `json:"kubearmorRelay,omitempty"`
	KubeArmorInit                    KubeArmorInitSpec       `json:"kubearmorInit,omitempty"`
	KubeRbacProxy                    KubeRbacProxySpec       `json:"kubeRbacProxy,omitempty"`
	KubeArmorController              KubeArmorControllerSpec `json:"kubearmorController,omitempty"`
	KubeArmorConfigMap               KubeArmorConfigMapSpec  `json:"kubearmorConfigMap,omitempty"`
	KubeArmor                        KubeArmorSpec           `json:"kubearmor,omitempty"`
}

// KubeArmorConfigStatus defines the observed state of KubeArmorConfig
type KubeArmorConfigStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +kubebuilder:validation:optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// SetCondition sets a new condition and return true if not exist or changed
// else returns false
func (status *KubeArmorConfigStatus) SetCondition(newCondition metav1.Condition) bool {
	newCondition.LastTransitionTime = metav1.Time{Time: time.Now()}
	for i, condition := range status.Conditions {
		if newCondition.Type == condition.Type {
			if newCondition.Status != condition.Status ||
				newCondition.Reason != condition.Reason ||
				newCondition.Message != condition.Message {
				status.Conditions[i] = newCondition
				return true
			}
			return false
		}
	}
	status.Conditions = append(status.Conditions, newCondition)
	return true
}

// RemoveCondition removes a condition by checking it's ty[e and return true
// else returns false
func (status *KubeArmorConfigStatus) RemoveCondition(conditionType string) bool {
	for i, c := range status.Conditions {
		if conditionType == c.Type {
			status.Conditions = append(status.Conditions[:i], status.Conditions[i+1:]...)
			return true
		}
	}
	return false
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:storageversion

// KubeArmorConfig is the Schema for the kubearmorconfigs API
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
