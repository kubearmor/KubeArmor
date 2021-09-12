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

func TestAppArmorEnforcer(t *testing.T) {
	// check AppArmor
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("Failed to access /sys/kernel/security/lsm")
	}
	lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("Failed to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("AppArmor is not enabled")
		return
	}

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.NodeIP = "nodeIP"
	node.EnableKubeArmorPolicy = true
	node.EnableKubeArmorHostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestAppArmorProfile(t *testing.T) {
	// check AppArmor
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("Failed to access /sys/kernel/security/lsm")
	}
	lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("Failed to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("AppArmor is not enabled")
		return
	}

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.NodeIP = "nodeIP"
	node.EnableKubeArmorPolicy = true
	node.EnableKubeArmorHostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// register AppArmorProfile
	if ok := enforcer.RegisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to register AppArmorProfile")
		return
	}
	t.Log("[PASS] Registered AppArmorProfile")

	// unregister AppArmorProfile
	if ok := enforcer.UnregisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to unregister AppArmorProfile")
		return
	}
	t.Log("[PASS] Unregister AppArmorProfile")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestHostAppArmorProfile(t *testing.T) {
	// check AppArmor
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("Failed to access /sys/kernel/security/lsm")
	}
	lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("Failed to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("AppArmor is not enabled")
		return
	}

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.NodeIP = "nodeIP"
	node.EnableKubeArmorPolicy = true
	node.EnableKubeArmorHostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}
