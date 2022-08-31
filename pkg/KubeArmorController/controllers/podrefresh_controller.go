// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controllers

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PodRefresherReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
		if strings.Contains(pod.Status.Message, "Cannot enforce AppArmor") {
			// the pod is managed by a controller (e.g: replicaset)
			if pod.OwnerReferences != nil && len(pod.OwnerReferences) != 0 {
				log.Info("Deleting pod " + pod.Name + "in namespace " + pod.Namespace + " as it is managed")
				if err := r.Delete(ctx, &pod); err != nil {
					log.Error(err, "Could not delete pod "+pod.Name+" in namespace "+pod.Namespace)
				}
			} else {
				// single pods
				// mimic kubectl replace --force
				// delete the pod --force ==> grace period equals zero
				log.Info("deleting single pod " + pod.Name + " in namespace " + pod.Namespace)
				if err := r.Delete(ctx, &pod, client.GracePeriodSeconds(0)); err != nil {
					log.Error(err, "Could'nt delete pod "+pod.Name+" in namespace "+pod.Namespace)
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
