// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type MacrosType struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KubeArmorMacroSpec defines the desired state of KubeArmorMacro
type KubeArmorMacroSpec struct {
	Macros []MacrosType `json:"macros"`
}

// KubeArmorMacroStatus defines the observed state of KubeArmorMacro
type KubeArmorMacroStatus struct {
	MacroStatus string `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// KubeArmorMacro is the Schema for the kubearmormacros API
type KubeArmorMacro struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KubeArmorMacroSpec   `json:"spec,omitempty"`
	Status KubeArmorMacroStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// KubeArmorMacroList contains a list of KubeArmorMacro
type KubeArmorMacroList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeArmorMacro `json:"items"`
}

func init() {
	SchemeBuilder.Register(&KubeArmorMacro{}, &KubeArmorMacroList{})
}
