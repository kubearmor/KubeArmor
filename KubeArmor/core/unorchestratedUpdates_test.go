// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"path/filepath"
	"strings"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

// TestPolicyBackupPath checks that a policy name cannot point the backup
// helpers at a file outside cfg.PolicyDir
func TestPolicyBackupPath(t *testing.T) {
	for _, name := range []string{"hsp-test", "ksp.test", "ksp_test-1"} {
		fname, ok := policyBackupPath(name)
		if !ok {
			t.Errorf("policy name %q rejected", name)
			continue
		}
		if fname != cfg.PolicyDir+name+".yaml" {
			t.Errorf("policy name %q gave unexpected backup path %q", name, fname)
		}
		if !strings.HasPrefix(filepath.Clean(fname), filepath.Clean(cfg.PolicyDir)+"/") {
			t.Errorf("policy name %q escapes the policy dir: %q", name, fname)
		}
	}

	for _, name := range []string{"", "..", "../escaped", "../../../tmp/escaped", "sub/escaped", `..\escaped`, "a..b"} {
		if fname, ok := policyBackupPath(name); ok {
			t.Errorf("policy name %q accepted with backup path %q", name, fname)
		}
	}
}
