/*
Copyright 2020-2021 AccuKnox.

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

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/accuknox/KubeArmor/pkg/KubeArmorHostPolicy/api/v1"
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

func (r *KubeArmorHostPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("kubearmorhostpolicy", req.NamespacedName)

	policy := securityv1.KubeArmorHostPolicy{}

	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Fetched KubeArmorHostPolicy")

	return ctrl.Result{}, nil
}

func (r *KubeArmorHostPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorHostPolicy{}).
		Complete(r)
}
