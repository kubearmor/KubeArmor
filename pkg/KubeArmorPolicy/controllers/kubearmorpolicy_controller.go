// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy/api/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

func (r *KubeArmorPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("kubearmorpolicy", req.NamespacedName)

	policy := &securityv1.KubeArmorPolicy{}

	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		return ctrl.Result{}, err
	}

	var policyErr error

	// Validate KubeArmorPolicy
	// if there are some issues in the policy the delete the policy and return failure code
	policyErr = validateProcessSchema(policy, req)
	if policyErr != nil {
		goto POLICYERROR
	}

	policyErr = validateFileSchema(policy, req)
	if policyErr != nil {
		goto POLICYERROR
	}

	policyErr = validateNetworkSchema(policy, req)
	if policyErr != nil {
		goto POLICYERROR
	}

	policyErr = validateCapabilitiesSchema(policy, req)
	if policyErr != nil {
		goto POLICYERROR
	}

POLICYERROR:
	if policyErr != nil {
		// Update PolicyStatus
		policy.Status.PolicyStatus = "Not OK"
		err := r.Status().Update(ctx, policy)
		log.Info("Invalid KubeArmorPolicy")
		// delete the invalid KubeArmorPolicy
		// err := r.Delete(ctx, policy)
		return ctrl.Result{}, err
	}

	// Update PolicyStatus
	policy.Status.PolicyStatus = "OK"
	err := r.Status().Update(ctx, policy)
	log.Info("Fetched KubeArmorPolicy")
	return ctrl.Result{}, err
}

func (r *KubeArmorPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.KubeArmorPolicy{}).
		Complete(r)
}

func validateProcessSchema(policy *securityv1.KubeArmorPolicy, req ctrl.Request) error {
	var policyErr error
	for _, matchPaths := range policy.Spec.Process.MatchPaths {
		if policy.Spec.Action != "Allow" {
			if matchPaths.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
		for _, fromSource := range matchPaths.FromSource {
			if fromSource.Path != "" {
				if fromSource.Recursive || !fromSource.Recursive {
					policyErr = fmt.Errorf("recursive is only effective with directories, not paths %v", req.NamespacedName)
					return policyErr
				}
			}
		}
	}
	for _, matchDirectories := range policy.Spec.Process.MatchDirectories {
		if policy.Spec.Action != "Allow" {
			if matchDirectories.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
	}
	for _, matchPatterns := range policy.Spec.Process.MatchPatterns {
		if policy.Spec.Action != "Allow" {
			if matchPatterns.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
	}
	return policyErr
}

func validateFileSchema(policy *securityv1.KubeArmorPolicy, req ctrl.Request) error {
	var policyErr error
	for _, matchPaths := range policy.Spec.File.MatchPaths {
		if policy.Spec.Action != "Allow" {
			if matchPaths.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
		for _, fromSource := range matchPaths.FromSource {
			if fromSource.Path != "" {
				if fromSource.Recursive || !fromSource.Recursive {
					policyErr = fmt.Errorf("Found invalid schema Recursive for Path %v", req.NamespacedName)
					return policyErr
				}
			}
		}
	}
	for _, matchDirectories := range policy.Spec.File.MatchDirectories {
		if policy.Spec.Action != "Allow" {
			if matchDirectories.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
	}
	for _, matchPatterns := range policy.Spec.File.MatchPatterns {
		if policy.Spec.Action != "Allow" {
			if matchPatterns.OwnerOnly {
				policyErr = fmt.Errorf("ownerOnly works with the Allow action %v", req.NamespacedName)
				return policyErr
			}
		}
	}
	return policyErr
}

func validateNetworkSchema(policy *securityv1.KubeArmorPolicy, req ctrl.Request) error {
	var policyErr error
	for _, matchProtocols := range policy.Spec.Network.MatchProtocols {
		for _, fromSource := range matchProtocols.FromSource {
			if fromSource.Path != "" {
				if fromSource.Recursive || !fromSource.Recursive {
					policyErr = fmt.Errorf("recursive is only effective with directories, not paths %v", req.NamespacedName)
					return policyErr
				}
			}
		}
	}
	return policyErr
}

func validateCapabilitiesSchema(policy *securityv1.KubeArmorPolicy, req ctrl.Request) error {
	var policyErr error
	for _, matchCapabilities := range policy.Spec.Capabilities.MatchCapabilities {
		for _, fromSource := range matchCapabilities.FromSource {
			if fromSource.Path != "" {
				if fromSource.Recursive || !fromSource.Recursive {
					policyErr = fmt.Errorf("recursive is only effective with directories, not paths %v", req.NamespacedName)
					return policyErr
				}
			}
		}
	}
	return policyErr
}
