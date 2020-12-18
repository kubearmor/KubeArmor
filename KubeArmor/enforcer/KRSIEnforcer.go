package enforcer

import (
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// =================== //
// == KRSI Enforcer == //
// =================== //

// KRSIEnforcer Structure
type KRSIEnforcer struct {
	//
}

// NewKRSIEnforcer Function
func NewKRSIEnforcer() *KRSIEnforcer {
	ke := &KRSIEnforcer{}
	return ke
}

// DestroyKRSIEnforcer Function
func (ke *KRSIEnforcer) DestroyKRSIEnforcer() {
	//
}

// UpdateSecurityPolicies Function
func (ke *KRSIEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	//
}
