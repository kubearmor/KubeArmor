// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controllers

import (
	"context"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// KubeArmorHostPolicyReconciler reconciles a KubeArmorHostPolicy object
type KubeArmorHostPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorhostpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorhostpolicies/status,verbs=get;update;patch

func (r *KubeArmorHostPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	// definig the kubectl-exec-policy
	policy := &securityv1.KubeArmorClusterPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alert-kubectl-exec",
		},
		Spec: securityv1.KubeArmorClusterPolicySpec{
			Severity: 1,
			Tags:     []string{"kubectl", "exec", "alert"},
			Message:  "Detected kubectl exec",
			Selector: securityv1.NsSelectorType{},
			Process: securityv1.ProcessType{
				MatchPatterns: []securityv1.ProcessPatternType{
					{Pattern: "ppid=0.*tty!=null",
						Action: securityv1.ActionType("Audit"),
					},
				},
			},
		},
	}
	// Check if the policy already exists
	existingPolicy := &securityv1.KubeArmorClusterPolicy{}
	err := r.Get(ctx, types.NamespacedName{Name: policy.Name}, existingPolicy)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Policy not found, create it
		if err := r.Create(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// Policy found, update it if necessary
		existingPolicy.Spec = policy.Spec
		if err := r.Update(ctx, existingPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *KubeArmorHostPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorHostPolicy{}).
		Complete(r)
}
