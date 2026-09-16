// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type RuntimeEnforcer interface {
	GetEnforcerType() string
	RegisterContainer(containerID string, pidns, mntns uint32)
	UnregisterContainer(containerID string)
	UpdateAppArmorProfiles(podName string, action string, profiles map[string]string, privilegedProfiles map[string]struct{})
	UpdateSecurityPolicies(endPoint tp.EndPoint)
	UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy)
	DestroyRuntimeEnforcer() error
}
