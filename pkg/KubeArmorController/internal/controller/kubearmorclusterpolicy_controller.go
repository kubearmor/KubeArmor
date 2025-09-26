// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/metrics"
	"k8s.io/apimachinery/pkg/runtime"
)

// KubeArmorClusterPolicyReconciler reconciles a KubeArmorClusterPolicy object
type KubeArmorClusterPolicyReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	EnableMetrics bool
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorclusterpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorclusterpolicies/status,verbs=get;update;patch

func (r *KubeArmorClusterPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kubearmorclusterpolicy", req.NamespacedName)

	// Get the policy
	policy := &securityv1.KubeArmorClusterPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if r.EnableMetrics && client.IgnoreNotFound(err) == nil {
			// Policy deleted - remove from metrics
			// Note: Cluster policies are cluster-scoped, so namespace is empty
			metrics.PolicyInfo.DeleteLabelValues(req.Name, "", "KubeArmorClusterPolicy", "active")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Update metrics if enabled
	if r.EnableMetrics {
		status := "active"
		if policy.Status.PolicyStatus != "" {
			status = policy.Status.PolicyStatus
		}

		// Cluster policies are cluster-scoped
		metrics.PolicyInfo.WithLabelValues(
			policy.Name, "", "KubeArmorClusterPolicy", status,
		).Set(1)

		// Update total count
		r.updatePolicyCount(ctx)
	}

	log.Info("Cluster policy reconciled successfully")
	return ctrl.Result{}, nil
}

// updatePolicyCount updates the total count of cluster policies
func (r *KubeArmorClusterPolicyReconciler) updatePolicyCount(ctx context.Context) {
	policyList := &securityv1.KubeArmorClusterPolicyList{}
	if err := r.List(ctx, policyList); err == nil {
		metrics.PolicyCount.WithLabelValues("KubeArmorClusterPolicy").Set(float64(len(policyList.Items)))
	}
}

func (r *KubeArmorClusterPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorClusterPolicy{}).
		Complete(r)
}
