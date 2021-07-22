// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
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

	// Create Feeder
	logFeeder := fd.NewFeeder("Default", "32767", "none", "policy", false)
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create SELinux Enforcer

	enforcer := NewSELinuxEnforcer(logFeeder)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create SELinux Enforcer")
		return
	}

	t.Log("[PASS] Created SELinux Enforcer")

	// Destroy SELinux Enforcer

	if err := enforcer.DestroySELinuxEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy SELinux Enforcer")
		return
	}

	t.Log("[PASS] Destroyed SELinux Enforcer")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}
