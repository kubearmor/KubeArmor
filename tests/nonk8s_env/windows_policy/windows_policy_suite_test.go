// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows

package windows_policy_test

import (
	"testing"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWindowsPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Windows Policy Test Suite")
}

var _ = BeforeSuite(func() {
	// Clear any leftover policies from previous runs to prevent cross-run pollution.
	// E.g., a cmd.exe block policy left over from a previous run would cause all
	// subsequent tests that spawn cmd.exe to fail with "Access is denied".
	policies := []string{
		"res/hsp-block-process-notepad.yaml",
		"res/hsp-block-process-cmd.yaml",
		"res/hsp-block-process-before-update.yaml",
		"res/hsp-block-process-after-update.yaml",
		"res/hsp-block-file-temp-pattern.yaml",
		"res/hsp-block-file-hosts.yaml",
	}
	for _, p := range policies {
		_ = SendPolicy("DELETED", p) // ignore errors — policy may not exist
	}
})

var _ = AfterSuite(func() {
	// Best-effort cleanup after the suite finishes.
	policies := []string{
		"res/hsp-block-process-notepad.yaml",
		"res/hsp-block-process-cmd.yaml",
		"res/hsp-block-process-before-update.yaml",
		"res/hsp-block-process-after-update.yaml",
		"res/hsp-block-file-temp-pattern.yaml",
		"res/hsp-block-file-hosts.yaml",
	}
	for _, p := range policies {
		_ = SendPolicy("DELETED", p)
	}
})
