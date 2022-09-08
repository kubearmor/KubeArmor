// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestFeeder(t *testing.T) {
	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// load configuration
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// create logger
	logger := NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}
