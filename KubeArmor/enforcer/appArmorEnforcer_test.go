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

	// Destroy AppArmor Enforcer

	t.Log("[INFO] Destroy AppArmor Enforcer")

	enforcer.DestroyAppArmorEnforcer()

	t.Log("[PASS] Destroyed AppArmor Enforcer")

	// == //
}
