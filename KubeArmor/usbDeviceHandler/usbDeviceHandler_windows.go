//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package usbdevicehandler

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ======================== //
// == USB Device Handler == //
// ======================== //

var (
	_ USBDeviceHandler = (*USBDeviceHandlerImpl)(nil)
)

// USBDeviceHandlerImpl Structure
type USBDeviceHandlerImpl struct {
	// logs
	Logger *fd.Feeder
	Rules  []EnforcementRule
}

// NewUSBDeviceHandler Function
func NewUSBDeviceHandler(logger *fd.Feeder) USBDeviceHandler {
	de := &USBDeviceHandlerImpl{}

	de.Logger = logger

	return de
}

// UpdateHostSecurityPolicies Function
func (de *USBDeviceHandlerImpl) UpdateHostSecurityPolicies(_ []tp.HostSecurityPolicy) {
	if de == nil {
		return
	}
}

func (de *USBDeviceHandlerImpl) GetRules() []EnforcementRule {
	return de.Rules
}

// DestroyUSBDeviceHandler Function
func (de *USBDeviceHandlerImpl) DestroyUSBDeviceHandler() error {
	// skip if USB device handler is not active
	if de == nil {
		return nil
	}

	// Reset Handler to nil if no errors during clean up
	de = nil
	return nil
}
