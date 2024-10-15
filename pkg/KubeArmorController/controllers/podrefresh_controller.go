// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/informer"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PodRefresherReconciler struct {
	client.Client
	Scheme  *runtime.Scheme
	Cluster *types.Cluster
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;watch;list;create;update;delete

func (r *PodRefresherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	var podList corev1.PodList
	if err := r.List(ctx, &podList); err != nil {
		log.Error(err, "Unable to list pods")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("Watching for blocked pods")
	poddeleted := false
	for _, pod := range podList.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Spec.NodeName == "" {
			continue
		}
		r.Cluster.ClusterLock.RLock()
		enforcer := ""
		if _, ok := r.Cluster.Nodes[pod.Spec.NodeName]; ok {
			enforcer = "apparmor"
		} else {
			enforcer = "bpf"
		}

		r.Cluster.ClusterLock.RUnlock()

		if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
			orginalPod := pod.DeepCopy()
			common.AddCommonAnnotations(&pod)
			patch := client.MergeFrom(orginalPod)
			err := r.Patch(ctx, &pod, patch)
			if err != nil {
				if !errors.IsNotFound(err) {
					log.Info(fmt.Sprintf("Failed to patch pod annotations: %s", err.Error()))
				}
			}
		}

		// restart not required for special pods and already annotated pods

		restartPod := requireRestart(pod, enforcer)

		if restartPod {
			// for annotating pre-existing pods on apparmor-nodes
			// the pod is managed by a controller (e.g: replicaset)
			if pod.OwnerReferences != nil && len(pod.OwnerReferences) != 0 {
				log.Info("Deleting pod " + pod.Name + "in namespace " + pod.Namespace + " as it is managed")
				if err := r.Delete(ctx, &pod); err != nil {
					if !errors.IsNotFound(err) {
						log.Error(err, "Could not delete pod "+pod.Name+" in namespace "+pod.Namespace)
					}
				}
			} else {
				// single pods
				// mimic kubectl replace --force
				// delete the pod --force ==> grace period equals zero
				log.Info("Deleting single pod " + pod.Name + " in namespace " + pod.Namespace)
				if err := r.Delete(ctx, &pod, client.GracePeriodSeconds(0)); err != nil {
					if !errors.IsNotFound(err) {
						log.Error(err, "Could'nt delete pod "+pod.Name+" in namespace "+pod.Namespace)
					}
				}

				// clean the pre-polutated attributes
				pod.ResourceVersion = ""

				// re-create the pod
				if err := r.Create(ctx, &pod); err != nil {
					log.Error(err, "Could not create pod "+pod.Name+" in namespace "+pod.Namespace)
				}
			}
			poddeleted = true
		}
	}
	// give time for pods to be deleted
	if poddeleted {
		time.Sleep(10 * time.Second)
	}

	return ctrl.Result{}, nil
}

func (r *PodRefresherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
func requireRestart(pod corev1.Pod, enforcer string) bool {

	if pod.Namespace == "kube-system" {
		return false
	}
	if _, ok := pod.Labels["io.cilium/app"]; ok {
		return false
	}

	if _, ok := pod.Labels["kubearmor-app"]; ok {
		return false
	}

	// !hasApparmorAnnotations && enforcer == "apparmor"
	if informer.HandleAppArmor(pod.Annotations) && enforcer == "apparmor" {
		return true
	}

	return false
}
