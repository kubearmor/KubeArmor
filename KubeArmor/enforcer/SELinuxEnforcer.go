package enforcer

import (
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	LogFeeder *fd.Feeder
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(feeder *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	se.LogFeeder = feeder

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	return nil
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	//
}
