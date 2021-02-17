package enforcer

import (
	"testing"

	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
)

func TestAppArmorEnforcer(t *testing.T) {
	// Create Feeder
	logFeeder := fd.NewFeeder("32767", "none")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

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
	// Create Feeder
	logFeeder := fd.NewFeeder("32767", "none")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

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
