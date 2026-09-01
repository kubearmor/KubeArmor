// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

// Package main runs the BPF-LSM bytecode load test.
package main

import "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"

func main() {
	bpflsm.TestCILoad()
}
