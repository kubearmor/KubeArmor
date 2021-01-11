package enforcer

import (
	"testing"
)

func TestAppArmorEnforcer(t *testing.T) {
	// Create AppArmor Enforcer

	enforcer := NewAppArmorEnforcer()
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
}

func TestAppArmorProfile(t *testing.T) {
	// Create AppArmor Enforcer

	enforcer := NewAppArmorEnforcer()
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
}
