package feeder

import (
	"testing"
	"time"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
	"github.com/accuknox/KubeArmor/LogServer/server"
)

func TestFeeder(t *testing.T) {
	server.Output = false

	// Start LogServer

	server := server.NewLogServer(":32767")
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

	auditFeeder := NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Destroy Feeder

	if err := auditFeeder.DestroyFeeder(); err != nil {
		t.Errorf("[FAIL] Failed to destroy Feeder (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	if err := server.DestroyLogServer(); err != nil {
		t.Errorf("[FAIL] Failed to destroy LogServer (%s)", err.Error())
		return
	}

	t.Log("[PASS] Stopped LogServer")
}

func TestDoHealthCheck(t *testing.T) {
	server.Output = false

	// Start LogServer

	server := server.NewLogServer(":32767")
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

	auditFeeder := NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check DoHealthCheck API

	if msg, ok := auditFeeder.DoHealthCheck(); !ok {
		t.Errorf("[FAIL] Failed to check DoHealthCheck API (%s)", msg)
		return
	}

	t.Log("[PASS] Checked DoHealthCheck API")

	// Destroy Feeder

	if err := auditFeeder.DestroyFeeder(); err != nil {
		t.Errorf("[FAIL] Failed to destroy Feeder (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	if err := server.DestroyLogServer(); err != nil {
		t.Errorf("[FAIL] Failed to destroy LogServer (%s)", err.Error())
		return
	}

	t.Log("[PASS] Stopped LogServer")
}

func TestSendAuditLog(t *testing.T) {
	server.Output = false

	// Start LogServer

	server := server.NewLogServer(":32767")
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

	auditFeeder := NewFeeder("localhost:32767", "AuditLog")
	if auditFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check SendAuditLog API

	auditLog := tp.AuditLog{}
	if err := auditFeeder.SendAuditLog(auditLog); err != nil {
		t.Errorf("[FAIL] Failed to send AuditLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Checked SendAuditLog API")

	// Destroy Feeder

	if err := auditFeeder.DestroyFeeder(); err != nil {
		t.Errorf("[FAIL] Failed to destroy Feeder (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	if err := server.DestroyLogServer(); err != nil {
		t.Errorf("[FAIL] Failed to destroy LogServer (%s)", err.Error())
		return
	}

	t.Log("[PASS] Stopped LogServer")
}

func TestSendSystemLog(t *testing.T) {
	server.Output = false

	// Start LogServer

	server := server.NewLogServer(":32767")
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

	systemFeeder := NewFeeder("localhost:32767", "SystemLog")
	if systemFeeder == nil {
		t.Error("[FAIL] Failed to create Feeder")
		return
	}

	t.Log("[PASS] Created Feeder")

	// Check SendSystemLog API

	systemLog := tp.SystemLog{}
	if err := systemFeeder.SendSystemLog(systemLog); err != nil {
		t.Errorf("[FAIL] Failed to send SystemLog (%s)", err.Error())
		return
	}

	t.Log("[PASS] Checked SendSystemLog API")

	// Destroy Feeder

	if err := systemFeeder.DestroyFeeder(); err != nil {
		t.Errorf("[FAIL] Failed to destroy Feeder (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed Feeder")

	// Stop LogServer

	if err := server.DestroyLogServer(); err != nil {
		t.Errorf("[FAIL] Failed to destroy LogServer (%s)", err.Error())
		return
	}

	t.Log("[PASS] Stopped LogServer")
}
