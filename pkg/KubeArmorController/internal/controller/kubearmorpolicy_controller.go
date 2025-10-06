// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// KubeArmorPolicyReconciler reconciles a KubeArmorPolicy object
type KubeArmorPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorpolicies/status,verbs=get;update;patch

func (r *KubeArmorPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	return ctrl.Result{}, nil
}

func (r *KubeArmorPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorPolicy{}).
		Complete(r)
}
