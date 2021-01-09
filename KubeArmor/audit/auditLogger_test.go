package audit

import (
	"os"
	"reflect"
	"sync"
	"testing"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestAuditLogger(t *testing.T) {
	// == //

	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// ActivePidMap
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// raw logs
	lines := []string{}

	// output values for validation
	auditTypeList := []string{}
	auditLogs := []tp.AuditLog{}

	// == //

	// Create AuditLogger

	t.Log("[INFO] Create AuditLogger (file:/tmp/kubearmor-audit.log)")

	auditLogger := NewAuditLogger("file:/tmp/kubearmor-audit.log", Containers, ContainersLock, ActivePidMap, ActivePidMapLock)
	if auditLogger == nil {
		t.Log("[FAIL] Failed to create AuditLogger")
		return
	}

	t.Log("[PASS] Created AuditLogger")

	// == //

	// Initialize AuditLogger

	t.Log("[INFO] Initialize AuditLogger")

	if err := auditLogger.InitAuditLogger("homeDir is not required in general"); err != nil {
		t.Errorf("[FAIL] %v", err)
		return
	}

	t.Log("[PASS] Initialized AuditLogger")

	// == //

	// Check GetAuditType() and GetAuditLog()

	t.Log("[INFO] Check GetAuditType() and GetAuditLog()")

	for idx, line := range lines {
		auditType := auditLogger.GetAuditType(line)
		if auditType == "" {
			t.Errorf("[FAIL] No auditType (%d)", idx)
			return
		} else if auditType != auditTypeList[idx] {
			t.Errorf("[FAIL] Incorrect auditType (%d, %s)", idx, auditType)
			return
		}

		auditLog := auditLogger.GetAuditLog(auditType, line)
		if !reflect.DeepEqual(auditLog, auditLogs[idx]) {
			t.Errorf("[FAIL] Incorrect auditLog (%d, %v)", idx, auditLog)
			return
		}

	}

	t.Log("[PASS] Checked GetAuditType() and GetAuditLog()")

	// == //

	// Destroy AuditLogger

	t.Log("[INFO] Destroy AuditLogger")

	if err := auditLogger.DestroyAuditLogger(); err != nil {
		t.Errorf("[FAIL] Failed to destroy AuditLogger (%s)", err.Error())
		return
	}

	t.Log("[PASS] Destroyed AuditLogger")

	// == //

	// Remove audit logs

	t.Log("[INFO] Remove /tmp/kubearmor-audit.log")

	if err := os.Remove("/tmp/kubearmor-audit.log"); err != nil {
		t.Errorf("[FAIL] Failed to remove /tmp/kubearmor-audit.log (%s)", err.Error())
		return
	}

	t.Log("[PASS] Removed /tmp/kubearmor-audit.log")

	// == //
}
