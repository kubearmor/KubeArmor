package server

import (
	"testing"
	"time"

	"github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestLogServer(t *testing.T) {
	// Start LogServer

	server := NewLogServer(":32767", "none", "none")
	if server == nil {
		t.Error("[FAIL] Failed to start LogServer")
		return
	}

	t.Log("[PASS] Started LogServer")

	// Start to receive logs

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Stop LogServer

	server.DestroyLogServer()

	t.Log("[PASS] Stopped LogServer")
}

func TestHealthCheckAPI(t *testing.T) {
	// Start LogServer

	server := NewLogServer(":32767", "none", "none")
	if server == nil {
		t.Error("[FAIL] Failed to start LogServer")
		return
	}

	t.Log("[PASS] Started LogServer")

	// Start to receive logs

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Create Feeder

	auditFeeder := feeder.NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check HealthCheck API

	msg, ok := auditFeeder.DoHealthCheck()
	if !ok {
		t.Errorf("[FAIL] Failed to check HealthCheck API (%s)", msg)
		return
	}

	t.Log("[PASS] Checked HealthCheck API")

	// Destroy Feeder

	auditFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	server.DestroyLogServer()

	t.Log("[PASS] Stopped LogServer")
}

func TestAuditLogsAPI(t *testing.T) {
	// Start LogServer

	server := NewLogServer(":32767", "none", "none")
	if server == nil {
		t.Error("[FAIL] Failed to start LogServer")
		return
	}

	t.Log("[PASS] Started LogServer")

	// Start to receive logs

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Create Feeder

	auditFeeder := feeder.NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check AuditLogs API

	auditLog := tp.AuditLog{}
	err := auditFeeder.SendAuditLog(auditLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send AuditLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Checked AuditLogs API")

	// Destroy Feeder

	auditFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	server.DestroyLogServer()

	t.Log("[PASS] Stopped LogServer")
}

func TestSystemLogsAPI(t *testing.T) {
	// Start LogServer

	server := NewLogServer(":32767", "none", "none")
	if server == nil {
		t.Error("[FAIL] Failed to start LogServer")
		return
	}

	t.Log("[PASS] Started LogServer")

	// Start to receive logs

	go server.ReceiveLogs()

	t.Log("[PASS] Started to receive logs")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Create Feeder

	systemFeeder := feeder.NewFeeder("localhost:32767", "SystemLog")
	if systemFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check SystemLogs API

	systemLog := tp.SystemLog{}
	err := systemFeeder.SendSystemLog(systemLog)
	if err != nil {
		t.Errorf("[FAIL] Failed to send SystemLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Checked SystemLogs API")

	// Destroy Feeder

	systemFeeder.DestroyFeeder()

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	server.DestroyLogServer()

	t.Log("[PASS] Stopped LogServer")
}
