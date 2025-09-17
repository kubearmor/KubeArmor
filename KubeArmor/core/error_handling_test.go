// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package core

import (
	"testing"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
)

// TestErrorHandlingRefactor validates that the refactored functions properly return errors
func TestErrorHandlingRefactor(t *testing.T) {
	// Test K8sHandler InitK8sClient with no K8s environment
	k8sHandler := NewK8sHandler()

	// Test InitK8sClient when not in K8s environment
	err := k8sHandler.InitK8sClient()
	if err == nil {
		t.Error("Expected error when not in K8s environment, got nil")
	}
	if err.Error() != "not running in Kubernetes environment" {
		t.Errorf("Expected specific error message, got: %s", err.Error())
	}

	// Test InitLocalAPIClient with invalid kubeconfig
	err = k8sHandler.InitLocalAPIClient()
	if err == nil {
		t.Error("Expected error when kubeconfig not found, got nil")
	}

	// Test KubeArmorDaemon InitLogger
	dm := NewKubeArmorDaemon()
	err = dm.InitLogger()
	if err != nil {
		// InitLogger might succeed or fail depending on environment
		// The important thing is that it returns an error type, not bool
		t.Logf("InitLogger returned error: %s", err.Error())
	} else {
		t.Log("InitLogger succeeded")
		if dm.Logger == nil {
			t.Error("Logger should not be nil when InitLogger succeeds")
		}
		// Clean up
		dm.CloseLogger()
	}

	// Test InitSystemMonitor with nil logger (should fail)
	dm2 := NewKubeArmorDaemon()
	dm2.Logger = nil
	err = dm2.InitSystemMonitor()
	if err == nil {
		t.Error("Expected error when logger is nil for InitSystemMonitor")
	}
}

// TestOriginalBehaviorPreserved ensures that the refactored functions maintain the same behavior
func TestOriginalBehaviorPreserved(t *testing.T) {
	// The key difference is now we get descriptive error messages instead of just true/false

	k8sHandler := NewK8sHandler()

	// Before: would return false
	// After: should return descriptive error
	err := k8sHandler.InitK8sClient()
	if err == nil && !kl.IsK8sEnv() {
		t.Error("Should return error when not in K8s environment")
	}
	if err != nil {
		// Verify we get a descriptive error, not just a boolean failure
		if len(err.Error()) == 0 {
			t.Error("Error message should not be empty")
		}
		t.Logf("Got descriptive error as expected: %s", err.Error())
	}
}