// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// getFreshEndPointForContainer re-reads the canonical endpoint under EndPointsLock.
func (dm *KubeArmorDaemon) getFreshEndPointForContainer(ns, epName, containerID string) (tp.EndPoint, bool) {
	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()

	for _, ep := range dm.EndPoints {
		if ep.NamespaceName == ns && ep.EndPointName == epName && kl.ContainsElement(ep.Containers, containerID) {
			return ep, true
		}
	}

	return tp.EndPoint{}, false
}

// bumpPolicyRevision increments the policy revision on an endpoint after a material policy change.
func bumpPolicyRevision(ep *tp.EndPoint) {
	ep.PolicyRevision++
}

// enforceEndpointSecurityPolicies applies security policies using a fresh endpoint snapshot.
func (dm *KubeArmorDaemon) enforceEndpointSecurityPolicies(action, ns, epName, containerID string) {
	if !cfg.GlobalCfg.Policy {
		return
	}

	freshEP, ok := dm.getFreshEndPointForContainer(ns, epName, containerID)
	if !ok || len(freshEP.SecurityPolicies) == 0 || freshEP.PolicyEnabled != tp.KubeArmorPolicyEnabled {
		return
	}

	if dm.Logger != nil {
		dm.Logger.UpdateSecurityPolicies(action, freshEP)
	}
	if dm.RuntimeEnforcer != nil {
		dm.RuntimeEnforcer.UpdateSecurityPolicies(freshEP)
	}
	if dm.Presets != nil {
		dm.Presets.UpdateSecurityPolicies(freshEP)
	}
}
