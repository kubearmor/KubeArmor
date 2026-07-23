// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package usbdevicehandler

import (
	"fmt"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// EnforcementRule describes USB enforcement settings.
type EnforcementRule struct {
	Class       int32
	SubClass    int32
	Protocol    int32
	Level       int32
	Action      string
	Specificity int32
}

// USBDeviceHandler is unsupported on non-Linux platforms.
type USBDeviceHandler struct{}

// NewUSBDeviceHandler returns nil on non-Linux platforms.
func NewUSBDeviceHandler(_ *fd.Feeder) *USBDeviceHandler {
	return nil
}

// UpdateHostSecurityPolicies is a no-op on non-Linux platforms.
func (de *USBDeviceHandler) UpdateHostSecurityPolicies(_ []tp.HostSecurityPolicy) {}

// DestroyUSBDeviceHandler reports that USB device handling is unsupported.
func (de *USBDeviceHandler) DestroyUSBDeviceHandler() error {
	return fmt.Errorf("USB device handling is only supported on Linux")
}
