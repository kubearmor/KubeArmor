package audit

import (
	"os"
	"reflect"
	"sync"
	"testing"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestAuditLogger(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// ActivePidMap
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// Create AuditLogger

	auditLogger := NewAuditLogger("file:/tmp/kubearmor-audit.log", Containers, ContainersLock, ActivePidMap, ActivePidMapLock)
	if auditLogger == nil {
		t.Log("[FAIL] Failed to create AuditLogger (file:/tmp/kubearmor-audit.log)")
		return
	}

	t.Log("[PASS] Created AuditLogger (file:/tmp/kubearmor-audit.log)")

	// Initialize AuditLogger

	if err := auditLogger.InitAuditLogger("homeDir is not required in general"); err != nil {
		t.Errorf("[FAIL] Failed to initialize AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Initialized AuditLogger")

	// Destroy AuditLogger

	if err := auditLogger.DestroyAuditLogger(); err != nil {
		t.Errorf("[FAIL] Failed to destroy AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed AuditLogger")

	// Remove audit log

	if err := os.Remove("/tmp/kubearmor-audit.log"); err != nil {
		t.Errorf("[FAIL] Failed to remove /tmp/kubearmor-audit.log (%s)", err.Error())
		return
	}

	t.Log("[PASS] Removed /tmp/kubearmor-audit.log")
}

func TestGetAuditType(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// ActivePidMap
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// raw logs
	lines := []string{}

	// expected auditTypes
	auditTypes := []string{}

	// Create AuditLogger

	auditLogger := NewAuditLogger("file:/tmp/kubearmor-audit.log", Containers, ContainersLock, ActivePidMap, ActivePidMapLock)
	if auditLogger == nil {
		t.Log("[FAIL] Failed to create AuditLogger (file:/tmp/kubearmor-audit.log)")
		return
	}

	t.Log("[PASS] Created AuditLogger (file:/tmp/kubearmor-audit.log)")

	// Initialize AuditLogger

	if err := auditLogger.InitAuditLogger("homeDir is not required in general"); err != nil {
		t.Errorf("[FAIL] Failed to initialize AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Initialized AuditLogger")

	// Check GetAuditType API

	for idx, line := range lines {
		auditType := auditLogger.GetAuditType(line)
		if auditType == "" {
			t.Errorf("[FAIL] No auditType (%d)", idx)
			return
		} else if auditType != auditTypes[idx] {
			t.Errorf("[FAIL] Incorrect auditType (%d, %s)", idx, auditType)
			return
		}
	}

	t.Log("[PASS] Checked GetAuditType API")

	// Destroy AuditLogger

	if err := auditLogger.DestroyAuditLogger(); err != nil {
		t.Errorf("[FAIL] Failed to destroy AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed AuditLogger")

	// Remove audit log

	if err := os.Remove("/tmp/kubearmor-audit.log"); err != nil {
		t.Errorf("[FAIL] Failed to remove /tmp/kubearmor-audit.log (%s)", err.Error())
		return
	}

	t.Log("[PASS] Removed /tmp/kubearmor-audit.log")
}

func TestGetAuditLog(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// ActivePidMap
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// raw logs
	lines := []string{}

	// expected auditLogs
	auditLogs := []tp.AuditLog{}

	// Create AuditLogger

	auditLogger := NewAuditLogger("file:/tmp/kubearmor-audit.log", Containers, ContainersLock, ActivePidMap, ActivePidMapLock)
	if auditLogger == nil {
		t.Log("[FAIL] Failed to create AuditLogger (file:/tmp/kubearmor-audit.log)")
		return
	}

	t.Log("[PASS] Created AuditLogger (file:/tmp/kubearmor-audit.log)")

	// Initialize AuditLogger

	if err := auditLogger.InitAuditLogger("homeDir is not required in general"); err != nil {
		t.Errorf("[FAIL] Failed to initialize AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Initialized AuditLogger")

	// Check GetAuditLog API

	t.Log("[INFO] Check GetAuditLog API")

	for idx, line := range lines {
		auditType := auditLogger.GetAuditType(line)
		if auditType == "" {
			t.Errorf("[FAIL] No auditType (%d)", idx)
			return
		}

		auditLog := auditLogger.GetAuditLog(auditType, line)
		if !reflect.DeepEqual(auditLog, auditLogs[idx]) {
			t.Errorf("[FAIL] Incorrect auditLog (%d, %v)", idx, auditLog)
			return
		}

	}

	t.Log("[PASS] Checked GetAuditLog API")

	// Destroy AuditLogger

	t.Log("[INFO] Destroy AuditLogger")

	if err := auditLogger.DestroyAuditLogger(); err != nil {
		t.Errorf("[FAIL] Failed to destroy AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed AuditLogger")

	// Remove audit log

	if err := os.Remove("/tmp/kubearmor-audit.log"); err != nil {
		t.Errorf("[FAIL] Failed to remove /tmp/kubearmor-audit.log (%s)", err.Error())
		return
	}

	t.Log("[PASS] Removed /tmp/kubearmor-audit.log")
}
