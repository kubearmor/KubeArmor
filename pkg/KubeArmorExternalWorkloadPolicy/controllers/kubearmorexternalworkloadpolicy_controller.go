// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorExternalWorkloadPolicy/api/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
)

// KubeArmorExternalWorkloadPolicyReconciler reconciles a KubeArmorExternalWorkloadPolicy object
type KubeArmorExternalWorkloadPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorexternalworkloadpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorexternalworkloadpolicies/status,verbs=get;update;patch

func (r *KubeArmorExternalWorkloadPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("kubearmorexternalworkloadpolicy", req.NamespacedName)

	policy := &securityv1.KubeArmorExternalWorkloadPolicy{}

	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		log.Info("Invalid KubeArmorExternalWorkloadPolicy")
		if errors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, err
	}

	// Validate KubeArmorPolicy
	// if there are some issues in the policy then delete the policy and return failure code
	//TODO: Handle the yaml spec validation

	log.Info("Fetched KubeArmorExternalWorkloadPolicy")
	return ctrl.Result{}, nil

}

func (r *KubeArmorExternalWorkloadPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorExternalWorkloadPolicy{}).
		Complete(r)
}
