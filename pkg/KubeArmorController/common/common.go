// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const k8sVisibility = "process,file,network,capabilities"
const appArmorAnnotation = "container.apparmor.security.beta.kubernetes.io/"
const KubeArmorRestartedAnnotation = "kubearmor.io/restarted"
const KubeArmorForceAppArmorAnnotation = "kubearmor.io/force-apparmor"

// == Add AppArmor annotations == //
func AppArmorAnnotator(pod *corev1.Pod) {
	podAnnotations := map[string]string{}
	var podOwnerName string

	// podOwnerName is the pod name for static pods and parent object's name
	// in other cases
	for _, ownerRef := range pod.ObjectMeta.OwnerReferences {
		// pod is owned by a replicaset, daemonset etc thus we use the managing
		// controller's name
		if ownerRef.Controller != nil && *ownerRef.Controller {
			podOwnerName = ownerRef.Name

			if ownerRef.Kind == "ReplicaSet" {
				// if it belongs to a replicaset, we also remove the pod template hash
				podOwnerName = strings.TrimSuffix(podOwnerName, fmt.Sprintf("-%s", pod.ObjectMeta.Labels["pod-template-hash"]))
			}
		}
	}

	if podOwnerName == "" {
		// pod is standalone, name remains constant
		podOwnerName = pod.ObjectMeta.Name
	}

	// Get existant kubearmor annotations
	for k, v := range pod.Annotations {
		if strings.HasPrefix(k, appArmorAnnotation) {
			if v == "unconfined" {
				containerName := strings.Split(k, "/")[1]
				podAnnotations[containerName] = v
			} else {
				containerName := strings.Split(k, "/")[1]
				podAnnotations[containerName] = strings.Split(v, "/")[1]
			}
		}
	}

	// Get the remaining containers / not addressed explecitly in the annotation
	for _, container := range pod.Spec.Containers {
		if _, ok := podAnnotations[container.Name]; !ok {
			podAnnotations[container.Name] = "kubearmor-" + pod.Namespace + "-" + podOwnerName + "-" + container.Name
		}
	}
	// Add kubearmor annotations to the pod
	for k, v := range podAnnotations {
		if v == "unconfined" {
			continue
		}
		pod.Annotations[appArmorAnnotation+k] = "localhost/" + v
	}
}
func AddCommonAnnotations(pod *corev1.Pod) {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}

	// == Policy == //

	if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
		// if no annotation is set enable kubearmor by default
		pod.Annotations["kubearmor-policy"] = "enabled"
	} else if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
		// if kubearmor policy is not set correctly, default it to enabled
		pod.Annotations["kubearmor-policy"] = "enabled"
	}
	// == Exception == //

	// exception: kubernetes app
	if pod.Namespace == "kube-system" {
		if _, ok := pod.Labels["k8s-app"]; ok {
			pod.Annotations["kubearmor-policy"] = "audited"
		}

		if value, ok := pod.Labels["component"]; ok {
			if value == "etcd" || value == "kube-apiserver" || value == "kube-controller-manager" || value == "kube-scheduler" || value == "kube-proxy" {
				pod.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	// exception: cilium-operator
	if _, ok := pod.Labels["io.cilium/app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// exception: kubearmor
	if _, ok := pod.Labels["kubearmor-app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// == Visibility == //

	if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
		pod.Annotations["kubearmor-visibility"] = k8sVisibility
	}
}

func RemoveApparmorAnnotation(pod *corev1.Pod) {
	annotations := []string{}

	for key := range pod.Annotations {
		if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") {
			annotations = append(annotations, key)
		}
	}
	for _, key := range annotations {
		delete(pod.Annotations, key)
	}
}
