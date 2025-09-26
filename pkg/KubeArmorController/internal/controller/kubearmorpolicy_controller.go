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

// KubeArmorPolicyReconciler reconciles a KubeArmorPolicy object
type KubeArmorPolicyReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	EnableMetrics bool
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorpolicies/status,verbs=get;update;patch

func (r *KubeArmorPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kubearmorpolicy", req.NamespacedName)

	// Get the policy
	policy := &securityv1.KubeArmorPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if r.EnableMetrics && client.IgnoreNotFound(err) == nil {
			// Policy deleted - remove from metrics
			metrics.PolicyInfo.DeleteLabelValues(req.Name, req.Namespace, "KubeArmorPolicy", "active")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Update metrics if enabled
	if r.EnableMetrics {
		status := "active"
		if policy.Status.PolicyStatus != "" {
			status = policy.Status.PolicyStatus
		}

		metrics.PolicyInfo.WithLabelValues(
			policy.Name, policy.Namespace, "KubeArmorPolicy", status,
		).Set(1)

		// Update total count
		r.updatePolicyCount(ctx)
	}

	log.Info("Policy reconciled successfully")
	return ctrl.Result{}, nil
}

// updatePolicyCount updates the total count of policies
func (r *KubeArmorPolicyReconciler) updatePolicyCount(ctx context.Context) {
	policyList := &securityv1.KubeArmorPolicyList{}
	if err := r.List(ctx, policyList); err == nil {
		metrics.PolicyCount.WithLabelValues("KubeArmorPolicy").Set(float64(len(policyList.Items)))
	}
}

func (r *KubeArmorPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorPolicy{}).
		Complete(r)
}
