// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

// Package bpflsm is responsible for setting/cleaning up objects for BPF LSM enforcer and handle updates for the same
package bpflsm

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// BPFEnforcer is a no-op placeholder on non-Linux platforms so that KubeArmor can
// be compiled on macOS and other non-Linux hosts for development and tooling.
type BPFEnforcer struct{}

// NewBPFEnforcer returns a nil enforcer on non-Linux platforms, causing the LSM
// selection logic to fall through to the next available enforcer.
func NewBPFEnforcer(node tp.Node, pinpath string, logger *fd.Feeder, monitor *mon.SystemMonitor) (*BPFEnforcer, error) {
	return nil, nil
}

// DestroyBPFEnforcer is a no-op on non-Linux platforms.
func (be *BPFEnforcer) DestroyBPFEnforcer() error { return nil }

// AddContainerIDToMap is a no-op on non-Linux platforms.
func (be *BPFEnforcer) AddContainerIDToMap(containerID string, pidns, mntns uint32) {}

// DeleteContainerIDFromMap is a no-op on non-Linux platforms.
func (be *BPFEnforcer) DeleteContainerIDFromMap(containerID string) {}

// UpdateSecurityPolicies is a no-op on non-Linux platforms.
func (be *BPFEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {}

// UpdateHostSecurityPolicies is a no-op on non-Linux platforms.
func (be *BPFEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {}
