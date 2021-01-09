package feeder

import (
	"testing"
	"time"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
	"github.com/accuknox/KubeArmor/LogServer/server"
)

func TestFeeder(t *testing.T) {
	server.Output = false

	// == //

	// Start LogServer

	t.Log("[INFO] Start LogServer")

	server := server.NewLogServer(":32767")

	t.Log("[PASS] Started LogServer")

	// == //

	// Start to receive logs

	t.Log("[INFO] Start to receive logs")

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// == //

	// Create Feeder for AuditLog

	t.Log("[INFO] Create Feeder for AuditLog")

	auditFeeder := NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder for AuditLog")

	// == //

	// Check DoHealthCheck()

	t.Log("[INFO] Check DoHealthCheck()")

	msg, ok := auditFeeder.DoHealthCheck()
	if !ok {
		t.Errorf("[FAIL] Failed to check DoHealthCheck() (%s)", msg)
		return
	}

	t.Log("[PASS] Checked DoHealthCheck()")

	// == //

	// Send AuditLog

	t.Log("[INFO] Send AuditLog")

	auditLog := tp.AuditLog{}
	err := auditFeeder.SendAuditLog(auditLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send AuditLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Sent AuditLog")

	// == //

	// Destroy Feeder for AuditLog

	t.Log("[INFO] Destroy Feeder for AuditLog")

	auditFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder for AuditLog")

	// == //

	time.Sleep(time.Second * 1)

	// == //

	// Create Feeder for SystemLog

	t.Log("[INFO] Create Feeder for SystemLog")

	systemFeeder := NewFeeder("localhost:32767", "SystemLog")
	if systemFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder for SystemLog")

	// == //

	// Send SystemLog

	t.Log("[INFO] Send SystemLog")

	systemLog := tp.SystemLog{}
	err = auditFeeder.SendSystemLog(systemLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send SystemLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Sent SystemLog")

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
