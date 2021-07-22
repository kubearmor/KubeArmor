// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package discovery

// ====================== //
// == Policy Discovery == //
// ====================== //

// PolicyDiscovery Structure
type PolicyDiscovery struct {
	//
}

// NewPolicyDiscovery Function
func NewPolicyDiscovery() *PolicyDiscovery {
	pd := &PolicyDiscovery{}
	return pd
}

// DestroyPolicyDiscovery Function
func (pd *PolicyDiscovery) DestroyPolicyDiscovery() error {
	return nil
}
