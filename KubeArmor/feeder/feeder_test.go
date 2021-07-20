package feeder

import (
	"testing"
)

func TestFeeder(t *testing.T) {
	// create Feeder
	feeder := NewFeeder("Default", "32767", "none", "policy", true)
	if feeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// destroy Feeder
	if err := feeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}
