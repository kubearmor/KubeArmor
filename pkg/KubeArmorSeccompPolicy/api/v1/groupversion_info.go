// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package v1 contains API Schema definitions for the security v1 API group
//+kubebuilder:object:generate=true
//+groupName=security.kubearmor.com
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "security.kubearmor.com", Version: "v1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
