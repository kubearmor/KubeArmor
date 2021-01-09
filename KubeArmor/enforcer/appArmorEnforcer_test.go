package enforcer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppArmorEnforcer(t *testing.T) {
	// == //

	// Get Home directory

	t.Log("[INFO] Get Home directory")

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		t.Errorf("[FAIL] Failed to get the home directory (%s)", err.Error())
		return
	}

	t.Log("[PASS] Got Home directory")

	// == //

	// Create AppArmor Enforcer

	t.Log("[INFO] Create AppArmor Enforcer")

	enforcer := NewAppArmorEnforcer(dir)

	t.Log("[PASS] Created AppArmor Enforcer")

	// == //

	// Register AppArmor Profile

	t.Log("[INFO] Register AppArmor Profile")

	if ok := enforcer.RegisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to register AppArmor Profile")
		return
	}

	t.Log("[PASS] Registered AppArmor Profile")

	// == //

	// Unregister AppArmor Profile

	t.Log("[INFO] Unregister AppArmor Profile")

	if ok := enforcer.UnregisterAppArmorProfile("test-profile"); !ok {
		t.Error("[FAIL] Failed to unregister AppArmor Profile")
		return
	}

	t.Log("[PASS] Unregistered AppArmor Profile")

	// == //

	// Destroy AppArmor Enforcer

	t.Log("[INFO] Destroy AppArmor Enforcer")

	enforcer.DestroyAppArmorEnforcer()

	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// == //
}
