// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

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

// KubeArmorHostPolicyReconciler reconciles a KubeArmorHostPolicy object
type KubeArmorHostPolicyReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	EnableMetrics bool
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorhostpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorhostpolicies/status,verbs=get;update;patch

func (r *KubeArmorHostPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kubearmorhostpolicy", req.NamespacedName)

	// Get the policy
	policy := &securityv1.KubeArmorHostPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if r.EnableMetrics && client.IgnoreNotFound(err) == nil {
			// Policy deleted - remove from metrics
			// Note: Host policies are cluster-scoped, so namespace is empty
			metrics.PolicyInfo.DeleteLabelValues(req.Name, "", "KubeArmorHostPolicy", "active")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Update metrics if enabled
	if r.EnableMetrics {
		status := "active"
		if policy.Status.PolicyStatus != "" {
			status = policy.Status.PolicyStatus
		}

		// Host policies are cluster-scoped
		metrics.PolicyInfo.WithLabelValues(
			policy.Name, "", "KubeArmorHostPolicy", status,
		).Set(1)

		// Update total count
		r.updatePolicyCount(ctx)
	}

	log.Info("Host policy reconciled successfully")
	return ctrl.Result{}, nil
}

// updatePolicyCount updates the total count of host policies
func (r *KubeArmorHostPolicyReconciler) updatePolicyCount(ctx context.Context) {
	policyList := &securityv1.KubeArmorHostPolicyList{}
	if err := r.List(ctx, policyList); err == nil {
		metrics.PolicyCount.WithLabelValues("KubeArmorHostPolicy").Set(float64(len(policyList.Items)))
	}
}

func (r *KubeArmorHostPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorHostPolicy{}).
		Complete(r)
}
