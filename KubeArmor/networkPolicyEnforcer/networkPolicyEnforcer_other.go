// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

// Package networkpolicyenforcer provides network policy enforcement. The real
// implementation is nftables/nflog based and Linux-only; this file is a no-op
// stub so KubeArmor can be built on other platforms for development and tooling.
package networkpolicyenforcer

import (
	"errors"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// NetworkPolicyEnforcer is a no-op placeholder on non-Linux platforms.
type NetworkPolicyEnforcer struct{}

// NewNetworkPolicyEnforcer returns an error on non-Linux platforms, causing the
// caller to log a warning and skip network policy enforcement.
func NewNetworkPolicyEnforcer(logger *fd.Feeder) (*NetworkPolicyEnforcer, error) {
	return nil, errors.New("network policy enforcement (nftables) is not supported on this platform")
}

// DestroyNetworkPolicyEnforcer is a no-op on non-Linux platforms.
func (ne *NetworkPolicyEnforcer) DestroyNetworkPolicyEnforcer() error { return nil }

// UpdateNetworkSecurityPolicies is a no-op on non-Linux platforms.
func (ne *NetworkPolicyEnforcer) UpdateNetworkSecurityPolicies(secPolicies []tp.NetworkSecurityPolicy, endpoints []tp.EndPoint, containers map[string]tp.Container) {
}
