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

func TestAppArmorEnforcer(t *testing.T) {
	// check AppArmor
	if _, err := os.Stat("/sys/kernel/security/lsm"); err != nil {
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("[INFO] AppArmor is not enabled")
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

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

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
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("[INFO] AppArmor is not enabled")
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

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// register AppArmorProfile
	if ok := enforcer.RegisterAppArmorProfile("test", "test-profile", true); !ok {
		t.Log("[FAIL] Failed to register AppArmorProfile")

		if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
			t.Log("[FAIL] Failed to destroy AppArmor Enforcer")

			if err := logger.DestroyFeeder(); err != nil {
				t.Log("[FAIL] Failed to destroy logger")
				return
			}

			return
		}

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Registered AppArmorProfile")

	// unregister AppArmorProfile
	if ok := enforcer.UnregisterAppArmorProfile("test", "test-profile", true); !ok {
		t.Log("[FAIL] Failed to unregister AppArmorProfile")

		if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
			t.Log("[FAIL] Failed to destroy AppArmor Enforcer")

			if err := logger.DestroyFeeder(); err != nil {
				t.Log("[FAIL] Failed to destroy logger")
				return
			}

			return
		}

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Unregister AppArmorProfile")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

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
		t.Log("[INFO] Unable to access /sys/kernel/security/lsm")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Log("[INFO] Unable to read /sys/kernel/security/lsm")
		return
	}
	if !strings.Contains(string(lsm), "apparmor") {
		t.Log("[INFO] AppArmor is not enabled")
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

	// create AppArmor Enforcer
	enforcer := NewAppArmorEnforcer(node, logger)
	if enforcer == nil {
		t.Log("[FAIL] Failed to create AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created AppArmor Enforcer")

	// destroy AppArmor Enforcer
	if err := enforcer.DestroyAppArmorEnforcer(); err != nil {
		t.Log("[FAIL] Failed to destroy AppArmor Enforcer")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

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
