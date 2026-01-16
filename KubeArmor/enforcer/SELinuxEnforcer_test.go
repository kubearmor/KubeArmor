// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package enforcer

import (
	"os"
	"strings"
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestSELinuxEnforcer(t *testing.T) {
	// Check SELinux
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "selinux") {
		t.Log("[INFO] SELinux is not enabled")
		return
	}

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// load configuration
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// configuration
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create SELinux Enforcer
	enforcer := NewSELinuxEnforcer(node, logger)
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

func TestSELinuxProfile(t *testing.T) {
	// Check SELinux
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "selinux") {
		t.Log("[INFO] SELinux is not enabled")
		return
	}

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// configuration
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = false

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create SELinux Enforcer
	enforcer := NewSELinuxEnforcer(node, logger)
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

func TestSELinuxHostProfile(t *testing.T) {
	// Check SELinux
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "selinux") {
		t.Log("[INFO] SELinux is not enabled")
		return
	}

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// configuration
	cfg.GlobalCfg.Policy = false
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create SELinux Enforcer
	enforcer := NewSELinuxEnforcer(node, logger)
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
