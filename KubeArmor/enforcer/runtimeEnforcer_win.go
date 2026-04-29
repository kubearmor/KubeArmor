//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

var (
	_ RuntimeEnforcer = (*RuntimeEnforcerImpl)(nil)
)

// RuntimeEnforcerImpl Structure
type RuntimeEnforcerImpl struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, logger *fd.Feeder, monitor *mon.SystemMonitor) RuntimeEnforcer {
	re := &RuntimeEnforcerImpl{}
	re.Logger = logger
	re.EnforcerType = "Minifilter"
	logger.UpdateEnforcer(re.EnforcerType)
	return re
}

func (re *RuntimeEnforcerImpl) GetEnforcerType() string {
	return re.EnforcerType
}

// RegisterContainer registers container identifiers to BPFEnforcer Map
func (re *RuntimeEnforcerImpl) RegisterContainer(containerID string, pidns, mntns uint32) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UnregisterContainer removes container identifiers from BPFEnforcer Map
func (re *RuntimeEnforcerImpl) UnregisterContainer(containerID string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcerImpl) UpdateAppArmorProfiles(podName string, action string, profiles map[string]string, privilegedProfiles map[string]struct{}) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcerImpl) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcerImpl) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcerImpl) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}
	return nil
}
