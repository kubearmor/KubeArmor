package core

import (
	"testing"

	"github.com/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestLogServer(t *testing.T) {
	Output = false

	// == //

	// Start LogServer

	t.Log("[INFO] Start LogServer")

	server := NewLogServer(":32767")

	t.Log("[PASS] Started LogServer")

	// == //

	// Start to receive logs

	t.Log("[INFO] Start to receive logs")

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// == //

	// Create Feeder for AuditLog

	t.Log("[INFO] Create Feeder for AuditLog")

	auditFeeder := feeder.NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder for AuditLog")

	// == //

	// Check HealthCheck API

	t.Log("[INFO] Check HealthCheck API")

	msg, ok := auditFeeder.DoHealthCheck()
	if !ok {
		t.Errorf("[FAIL] Failed to check HealthCheck API (%s)", msg)
		return
	}

	t.Log("[PASS] Checked HealthCheck API")

	// == //

	// Check AuditLogs API

	t.Log("[INFO] Test AuditLogs API")

	auditLog := tp.AuditLog{}
	err := auditFeeder.SendAuditLog(auditLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send AuditLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Tested AuditLogs API")

	// == //

	// Destroy Feeder for AuditLog

	t.Log("[INFO] Destroy Feeder for AuditLog")

	auditFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder for AuditLog")

	// == //

	// Create Feeder for SystemLog

	t.Log("[INFO] Create Feeder for SystemLog")

	systemFeeder := feeder.NewFeeder("localhost:32767", "SystemLog")
	if systemFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder for SystemLog")

	// == //

	// Check SystemLogs API

	t.Log("[INFO] Check SystemLogs API")

	systemLog := tp.SystemLog{}
	err = auditFeeder.SendSystemLog(systemLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send SystemLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Checked SystemLogs API")

	// == //

	// Destroy Feeder for SystemLog

	t.Log("[INFO] Destroy Feeder for SystemLog")

	systemFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder for SystemLog")

	// == //

	// Stop LogServer

	t.Log("[INFO] Stop LogServer")

	server.DestroyLogServer()

	t.Log("[PASS] Stopped LogServer")

	// == //
}
