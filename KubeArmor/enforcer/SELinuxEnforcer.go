// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	//
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(node tp.Node, logger *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}
	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	return nil
}

// ================================ //
// == SELinux Profile Management == //
// ================================ //

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(podName, profileName string) bool {
	return true
}

// UnregisterSELinuxProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(podName, profileName string) bool {
	return true
}

// ===================================== //
// == SELinux Host Profile Management == //
// ===================================== //

// RegisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxHostProfile() bool {
	return true
}

// UnregisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxHostProfile() bool {
	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateSELinuxProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxProfile(endPoint tp.EndPoint, seLinuxProfile string, securityPolicies []tp.SecurityPolicy) {
	//
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return
	}

	selinuxProfiles := []string{}

	for _, seLinuxProfile := range endPoint.SELinuxProfiles {
		if !kl.ContainsElement(selinuxProfiles, seLinuxProfile) {
			selinuxProfiles = append(selinuxProfiles, seLinuxProfile)
		}
	}

	if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
		for _, selinuxProfile := range selinuxProfiles {
			se.UpdateSELinuxProfile(endPoint, selinuxProfile, endPoint.SecurityPolicies)
		}
	} else { // PolicyDisabled
		for _, selinuxProfile := range selinuxProfiles {
			se.UpdateSELinuxProfile(endPoint, selinuxProfile, []tp.SecurityPolicy{})
		}
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateSELinuxHostProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxHostProfile(secPolicies []tp.HostSecurityPolicy) {
	//
}

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return
	}

	if cfg.GlobalCfg.HostPolicy {
		se.UpdateSELinuxHostProfile(secPolicies)
	} else {
		se.UpdateSELinuxHostProfile([]tp.HostSecurityPolicy{})
	}
}
