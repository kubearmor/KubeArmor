// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package usbdevicehandler

import tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

// EnforcementRule Structure
type EnforcementRule struct {
	Class       int32
	SubClass    int32
	Protocol    int32
	Level       int32
	Action      string
	Specificity int32 // to handle conflicts between class/subclass/protocol
}

// USBDeviceHandler Structure
type USBDeviceHandler interface {
	UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy)
	DestroyUSBDeviceHandler() error
	GetRules() []EnforcementRule
}
