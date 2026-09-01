// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package monitor

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// ImaHash is a no-op placeholder on non-Linux platforms so that KubeArmor can be
// compiled on macOS and other non-Linux hosts for development and tooling.
type ImaHash struct{}

// NewImaHash is a no-op on non-Linux platforms and is never reached at runtime,
// since IMA hashing is gated behind a successful BPF-LSM probe.
func NewImaHash(logger *fd.Feeder, pinPath string) (*ImaHash, error) {
	return nil, nil
}

// DestroyImaHash is a no-op on non-Linux platforms.
func (ih *ImaHash) DestroyImaHash() error {
	return nil
}
