// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestSELinuxEnforcer(t *testing.T) {
	// Check SELinux
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("Failed to access /sys/kernel/security/lsm")
	}
	lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("Failed to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "selinux") {
		t.Log("SELinux is not enabled")
		return
	}

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.NodeIP = "nodeIP"
	node.EnableKubeArmorPolicy = true
	node.EnableKubeArmorHostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", &node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create SELinux Enforcer
	enforcer := NewSELinuxEnforcer(logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create SELinux Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created SELinux Enforcer")

	// destroy SELinux Enforcer
	if err := enforcer.DestroySELinuxEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy SELinux Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Destroyed SELinux Enforcer")

	// destroy Feeder
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}
