// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package usbdevicehandler

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// USBDeviceHandler is a no-op placeholder on non-Linux platforms, where USB
// device observability (which relies on netlink uevents) is unavailable. KubeArmor
// is only built on such platforms for development and tooling.
type USBDeviceHandler struct{}

// NewUSBDeviceHandler returns nil on non-Linux platforms, causing the caller to
// treat the USB device handler as unavailable.
func NewUSBDeviceHandler(logger *fd.Feeder) *USBDeviceHandler {
	return nil
}

// UpdateHostSecurityPolicies is a no-op on non-Linux platforms.
func (de *USBDeviceHandler) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {}

// DestroyUSBDeviceHandler is a no-op on non-Linux platforms.
func (de *USBDeviceHandler) DestroyUSBDeviceHandler() error { return nil }
