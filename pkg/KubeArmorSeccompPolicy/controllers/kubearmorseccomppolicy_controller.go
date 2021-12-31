/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorSeccompPolicy/api/v1"
)

// KubeArmorSeccompPolicyReconciler reconciles a KubeArmorSeccompPolicy object
type KubeArmorSeccompPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorseccomppolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorseccomppolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.kubearmor.com,resources=kubearmorseccomppolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KubeArmorSeccompPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *KubeArmorSeccompPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("kubearmorseccomppolicy", req.NamespacedName)

	policy := &securityv1.KubeArmorSeccompPolicy{}

	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, err
	}

	var err error = nil

	// Add validation here, if necessary
	if err != nil {
		// Update PolicyStatus
		policy.Status.PolicyStatus = "Not OK"
		err := r.Status().Update(ctx, policy)
		log.Info("Invalid KubeArmorSeccompPolicy")
		return ctrl.Result{}, err
	}

	// Update PolicyStatus
	policy.Status.PolicyStatus = "OK"
	err = r.Status().Update(ctx, policy)
	log.Info("Fetched KubeArmorPolicy")
	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *KubeArmorSeccompPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorSeccompPolicy{}).
		Complete(r)
}
