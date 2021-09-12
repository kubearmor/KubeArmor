// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

func TestAppArmorEnforcer(t *testing.T) {
	// Check AppArmor
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

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}
	t.Log("[PASS] Created Feeder")

	// Create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(logFeeder)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// Destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}
	t.Log("[PASS] Destroyed Feeder")
}

func TestAppArmorProfile(t *testing.T) {
	// Check AppArmor
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

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}
	t.Log("[PASS] Created Feeder")

	// Create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(logFeeder)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// Register AppArmorProfile
	if ok := enforcer.RegisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to register AppArmorProfile")
		return
	}
	t.Log("[PASS] Registered AppArmorProfile")

	// Unregister AppArmorProfile
	if ok := enforcer.UnregisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to unregister AppArmorProfile")
		return
	}
	t.Log("[PASS] Unregister AppArmorProfile")

	// Destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")
		return
	}
	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}
	t.Log("[PASS] Destroyed Feeder")
}
