package enforcer

import (
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	//
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer() *SELinuxEnforcer {
	se := &SELinuxEnforcer{}
	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() {
	//
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	//
}
