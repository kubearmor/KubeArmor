// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// =================== //
// == KRSI Enforcer == //
// =================== //

// KRSIEnforcer Structure
type KRSIEnforcer struct {
	// logs
	LogFeeder *fd.Feeder
}

// NewKRSIEnforcer Function
func NewKRSIEnforcer(feeder *fd.Feeder) *KRSIEnforcer {
	ke := &KRSIEnforcer{}

	ke.LogFeeder = feeder

	return ke
}

// DestroyKRSIEnforcer Function
func (ke *KRSIEnforcer) DestroyKRSIEnforcer() error {
	return nil
}

// UpdateSecurityPolicies Function
func (ke *KRSIEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	//
}

// UpdateHostSecurityPolicies Function
func (ke *KRSIEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	//
}
