// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

import (
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// log is for logging in this package.
var kubearmorconfiglog = logf.Log.WithName("kubearmorconfig-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *KubeArmorConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
