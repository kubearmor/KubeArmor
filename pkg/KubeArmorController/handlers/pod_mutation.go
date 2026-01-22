// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodAnnotator Structure
type PodAnnotator struct {
	Client    client.Client
	Decoder   admission.Decoder
	Logger    logr.Logger
	Cluster   *types.Cluster
	ClientSet *kubernetes.Clientset
}

// +kubebuilder:webhook:path=/mutate-pods,mutating=true,failurePolicy=Ignore,groups="",resources=pods;pods/binding,verbs=create;update,versions=v1,name=annotation.kubearmor.com,admissionReviewVersions=v1,sideEffects=NoneOnDryRun

// Handle Pod Annotation
func (a *PodAnnotator) Handle(ctx context.Context, req admission.Request) admission.Response {

	// if it is pod/binding event
	if req.Kind.Kind == "Binding" {
		binding := &corev1.Binding{}
		if err := a.Decoder.Decode(req, binding); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		// Decode will omit sometimes the namespace value for some reason copying it manually
		if binding.Namespace == "" {
			binding.Namespace = req.Namespace
		}

		// == common annotations == //
		common.AddCommonAnnotations(&binding.ObjectMeta)

		pod, err := a.ClientSet.CoreV1().Pods(binding.Namespace).Get(context.TODO(), binding.Name, metav1.GetOptions{})
		if err != nil {
			a.Logger.Error(err, "failed to get pod info")
		}
		nodename := binding.Target.Name
		annotate := false
		// == Apparmor annotations == //
		a.Cluster.ClusterLock.RLock()
		// homogenousApparmor := a.Cluster.HomogenousApparmor
		if _, exist := a.Cluster.Nodes[nodename]; exist {
			if a.Cluster.Nodes[nodename].KubeArmorActive {
				annotate = true
			}
		}
		a.Cluster.ClusterLock.RUnlock()
		if annotate {
			common.AppArmorAnnotator(pod, binding, true)
		}
		// == //
		// send the mutation response
		marshaledPod, err := json.Marshal(binding)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)

	}
	// If it is pod CreateEvent
	pod := &corev1.Pod{}
	if err := a.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if pod.Spec.NodeName != "" {

		// Decode will omit sometimes the namespace value for some reason copying it manually
		if pod.Namespace == "" {
			pod.Namespace = req.Namespace
		}
		// == common annotations == //
		common.AddCommonAnnotations(&pod.ObjectMeta)
		nodename := pod.Spec.NodeName
		annotate := false
		// == Apparmor annotations == //
		a.Cluster.ClusterLock.RLock()
		// homogenousApparmor := a.Cluster.HomogenousApparmor
		if _, exist := a.Cluster.Nodes[nodename]; exist {
			if a.Cluster.Nodes[nodename].KubeArmorActive {
				annotate = true
			}
		}
		a.Cluster.ClusterLock.RUnlock()
		if annotate {
			common.AppArmorAnnotator(pod, nil, false)
		}

	}
	// == //
	// send the mutation response
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)

}
