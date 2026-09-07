// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows

package windows_policy_test

import (
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// appLockerAlertTimeout is longer than on Linux because the AppLocker event-log
// poller runs every 5 seconds; we allow ≥4 polling cycles plus processing time.
const appLockerAlertTimeout = 30 * time.Second

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Specs
// ──────────────────────────────────────────────────────────────────────────────

var _ = Describe("Windows Policy Tests", func() {

	// ─────────────────────────────────────────────────────────
	// Suite 1: Policy application smoke tests
	// Verify policies can be applied/deleted over gRPC without
	// needing to check enforcement output.
	// ─────────────────────────────────────────────────────────
	Describe("Policy Application", func() {
		It("can apply and delete a process block policy", func() {
			policyPath := "res/hsp-block-process-notepad.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			time.Sleep(2 * time.Second)

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("can apply and delete a file block policy", func() {
			policyPath := "res/hsp-block-file-temp-pattern.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			time.Sleep(2 * time.Second)

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("can replace one policy with an updated version", func() {
			beforeUpdate := "res/hsp-block-process-before-update.yaml"
			afterUpdate := "res/hsp-block-process-after-update.yaml"

			err := SendPolicy("ADDED", beforeUpdate)
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", afterUpdate)
			Expect(err).To(BeNil())

			time.Sleep(2 * time.Second)

			err = SendPolicy("DELETED", afterUpdate)
			Expect(err).To(BeNil())
		})
	})

	// ─────────────────────────────────────────────────────────
	// Suite 2: Process block enforcement via AppLocker
	//
	// Requires the Application Identity (AppIDSvc) service to be
	// running, which is present on windows-2022 GitHub-hosted
	// runners. AppLocker block events (8004) are picked up by the
	// KubeArmor event-log poller (5 s interval) and forwarded as
	// MatchedHostPolicy alerts over gRPC.
	// ─────────────────────────────────────────────────────────
	Describe("Process Block Enforcement (AppLocker)", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(2 * time.Second)
		})

		It("should block notepad.exe execution and generate an alert", func() {
			policyPath := "res/hsp-block-process-notepad.yaml"

			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			// defer ensures cleanup even when Expect() fails and calls runtime.Goexit()
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			// Allow AppLocker time to pick up the new policy before triggering.
			time.Sleep(3 * time.Second)

			// Attempt to run notepad.exe; expect access denied from AppLocker.
			AssertWindowsCommand(
				[]string{"start", "/wait", "notepad.exe"},
				Or(
					MatchRegexp(`(?i)access.*(denied|blocked|is not accessible)`),
					MatchRegexp(`(?i)This program is blocked by group policy`),
				),
				false,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-notepad-exec",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("should block cmd.exe execution and generate an alert", func() {
			policyPath := "res/hsp-block-process-cmd.yaml"

			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			time.Sleep(3 * time.Second)

			// Spawning a child cmd.exe sub-process will be blocked by AppLocker.
			AssertWindowsCommand(
				[]string{"cmd.exe", "/C", "echo kubearmor-test"},
				Or(
					MatchRegexp(`(?i)access.*(denied|blocked)`),
					MatchRegexp(`(?i)This program is blocked by group policy`),
				),
				false,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-cmd-exec",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("should allow execution again after the block policy is deleted", func() {
			policyPath := "res/hsp-block-process-notepad.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Wait for AppLocker to apply.
			time.Sleep(4 * time.Second)

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())

			// Wait for AppLocker to clear the deny rule.
			time.Sleep(4 * time.Second)

			// Start notepad in background and immediately kill it — the absence
			// of an AppLocker denial message is the key assertion.
			AssertWindowsCommand(
				[]string{"start", "/B", "notepad.exe", "&&", "taskkill", "/F", "/IM", "notepad.exe"},
				Not(MatchRegexp(`(?i)This program is blocked by group policy`)),
				false,
			)
		})
	})

	// ─────────────────────────────────────────────────────────
	// Suite 3: Policy update changes enforcement correctly
	// ─────────────────────────────────────────────────────────
	Describe("Process Policy Update", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(2 * time.Second)
		})

		It("should update enforcement when policy is replaced", func() {
			beforeUpdate := "res/hsp-block-process-before-update.yaml"
			afterUpdate := "res/hsp-block-process-after-update.yaml"

			// Phase 1: beforeUpdate blocks notepad.exe
			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", beforeUpdate)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", beforeUpdate) //nolint:errcheck

			time.Sleep(3 * time.Second)

			AssertWindowsCommand(
				[]string{"start", "/wait", "notepad.exe"},
				Or(
					MatchRegexp(`(?i)access.*(denied|blocked)`),
					MatchRegexp(`(?i)This program is blocked by group policy`),
				),
				false,
			)

			// Phase 2: afterUpdate blocks calc.exe instead of notepad.exe
			err = SendPolicy("ADDED", afterUpdate)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", afterUpdate) //nolint:errcheck

			time.Sleep(3 * time.Second)

			// notepad.exe should now be allowed
			AssertWindowsCommand(
				[]string{"start", "/B", "notepad.exe", "&&", "taskkill", "/F", "/IM", "notepad.exe"},
				Not(MatchRegexp(`(?i)This program is blocked by group policy`)),
				false,
			)

			// calc.exe should now be blocked
			AssertWindowsCommand(
				[]string{"start", "/wait", "calc.exe"},
				Or(
					MatchRegexp(`(?i)access.*(denied|blocked)`),
					MatchRegexp(`(?i)This program is blocked by group policy`),
				),
				false,
			)
		})
	})

	// ─────────────────────────────────────────────────────────
	// Suite 4: File block enforcement via minifilter driver
	//
	// Requires the KubeArmor minifilter (kubearmor.sys) to be
	// loaded.
	// ─────────────────────────────────────────────────────────
	Describe("File Block Enforcement (Minifilter Driver)", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(2 * time.Second)
		})

		It("should block file writes under C:\\Temp\\* via pattern rule and generate an alert", func() {
			policyPath := "res/hsp-block-file-temp-pattern.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			// Ensure the target directory exists
			_, _ = RunWindowsCommand([]string{"if", "not", "exist", `C:\Temp`, "mkdir", `C:\Temp`})

			// Attempt to write a file — minifilter should block it
			AssertWindowsCommand(
				[]string{"echo", "kubearmor-test", ">", `C:\Temp\ka_test.txt`},
				Or(
					MatchRegexp(`(?i)Access is denied`),
					MatchRegexp(`(?i)The process cannot access the file`),
				),
				false,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-file-temp",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("should block read of the Windows hosts file and generate an alert", func() {
			policyPath := "res/hsp-block-file-hosts.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			AssertWindowsCommand(
				[]string{"type", `C:\Windows\System32\drivers\etc\hosts`},
				Or(
					MatchRegexp(`(?i)Access is denied`),
					MatchRegexp(`(?i)The process cannot access the file`),
				),
				false,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-hosts-file",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────
	// Suite 5: Process audit via minifilter driver
	//
	// Audit policies send the rule to the minifilter driver with
	// ruleActionAudit. The driver allows the process to run but
	// fires a MatchHostPolicy event so KubeArmor generates an
	// alert with Action="Audit" and Result="Passed".
	// AppLocker is NOT configured for audit-mode rules (its global
	// EnforcementMode stays "Enabled"). The minifilter is the sole
	// observer for these rules.
	// ─────────────────────────────────────────────────────────
	Describe("Process Audit Enforcement (Minifilter Driver)", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(2 * time.Second)
		})

		It("should audit notepad.exe execution and generate an Audit alert without blocking", func() {
			policyPath := "res/hsp-audit-process-notepad.yaml"

			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			time.Sleep(3 * time.Second)

			// Execution must succeed — Audit mode does NOT block the process.
			AssertWindowsCommand(
				[]string{"start", "/B", "notepad.exe", "&&", "taskkill", "/F", "/IM", "notepad.exe"},
				Not(MatchRegexp(`(?i)This program is blocked by group policy`)),
				false,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-notepad-exec",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})

	// ─────────────────────────────────────────────────────────
	// Suite 6: File audit via minifilter driver
	//
	// Audit policies for files allow the file operation through
	// while generating a MatchedHostPolicy alert with
	// Action="Audit" and Result="Passed".
	// ─────────────────────────────────────────────────────────
	Describe("File Audit Enforcement (Minifilter Driver)", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(2 * time.Second)
		})

		It("should audit file writes under C:\\Temp\\* via pattern rule without blocking", func() {
			policyPath := "res/hsp-audit-file-temp-pattern.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			// Ensure target directory exists
			_, _ = RunWindowsCommand([]string{"if", "not", "exist", `C:\Temp`, "mkdir", `C:\Temp`})

			// Write must succeed — Audit mode does NOT block the operation.
			AssertWindowsCommand(
				[]string{"echo", "kubearmor-audit-test", ">", `C:\Temp\ka_audit_test.txt`},
				Not(MatchRegexp(`(?i)Access is denied`)),
				true,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-file-temp",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("should audit read of the Windows hosts file without blocking", func() {
			policyPath := "res/hsp-audit-file-hosts.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
			defer SendPolicy("DELETED", policyPath) //nolint:errcheck

			// Read must succeed — Audit mode does NOT block the operation.
			AssertWindowsCommand(
				[]string{"type", `C:\Windows\System32\drivers\etc\hosts`},
				Not(MatchRegexp(`(?i)Access is denied`)),
				true,
			)

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-hosts-file",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(appLockerAlertTimeout, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})
})
