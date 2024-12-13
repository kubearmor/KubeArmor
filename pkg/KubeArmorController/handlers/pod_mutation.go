// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// PodAnnotator Structure
type PodAnnotator struct {
	Client  client.Client
	Decoder admission.Decoder
	Logger  logr.Logger
	Cluster *types.Cluster
}

// +kubebuilder:webhook:path=/mutate-pods,mutating=true,failurePolicy=Ignore,groups="",resources=pods,verbs=create;update,versions=v1,name=annotation.kubearmor.com,admissionReviewVersions=v1,sideEffects=NoneOnDryRun

// Handle Pod Annotation
func (a *PodAnnotator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}

	if err := a.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Decode will omit sometimes the namespace value for some reason copying it manually
	if pod.Namespace == "" {
		pod.Namespace = req.Namespace
	}

	// == common annotations == //
	common.AddCommonAnnotations(pod)

	// == Apparmor annotations == //
	a.Cluster.ClusterLock.RLock()
	homogenousApparmor := a.Cluster.HomogenousApparmor
	a.Cluster.ClusterLock.RUnlock()

	if homogenousApparmor {
		common.AppArmorAnnotator(pod)
	}

	// == //
	// send the mutation response
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}
