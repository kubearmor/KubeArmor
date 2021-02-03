package enforcer

import (
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
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
