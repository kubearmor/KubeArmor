// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package host_policy_test

import (
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Host Policy Tests", func() {
	Describe("Karmor Log", func() {
		It("should generate a host log when /usr/bin/ls is blocked", func() {
			policyPath := "res/hsp-block-process-ls.yaml"

			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"ls", "-l"}, MatchRegexp(`(?i)permission denied`), false)

			target := &protobuf.Alert{Result: "Permission denied"}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
			KarmorLogStop()
			time.Sleep(3 * time.Second)
		})
	})

	Describe("Apply and Update Host Policies", func() {
		It("should apply, update, and enforce process block policy successfully", func() {
			beforeUpdate := "res/hsp-block-process-before-update.yaml"
			afterUpdate := "res/hsp-block-process-after-update.yaml"

			err := SendPolicy("ADDED", beforeUpdate)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"curl", "--version"}, MatchRegexp(`(?i)permission denied`), false)

			err = SendPolicy("ADDED", afterUpdate)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"curl", "--version"}, Not(MatchRegexp(`(?i)permission denied`)), false)
			AssertHostCommand([]string{"ls"}, MatchRegexp(`(?i)permission denied`), false)

			err = SendPolicy("DELETED", afterUpdate)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"ls"}, Not(MatchRegexp(`(?i)permission denied`)), false)
		})
	})

	Describe("Host Policy Enforcement", func() {
		AfterEach(func() {
			KarmorLogStop()
			time.Sleep(time.Second * 2)
		})

		It("should block access to files under /tmp/*", func() {
			policyPath := "res/hsp-block-file-pattern.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			_, _ = RunHostCommand([]string{"echo", "hello", ">", "/tmp/something.txt"})

			target := &protobuf.Alert{
				PolicyName: "hsp-block-file-pattern",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should generate a host log when unlink is called under audit policy", func() {
			policyPath := "res/hsp-audit-syscall.yaml"

			err := KarmorHostLogStart("policy", "Syscall")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			_, _ = RunHostCommand([]string{"touch", "/tmp/dummy"})
			_, _ = RunHostCommand([]string{"unlink", "/tmp/dummy"})

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-syscall",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should audit when process in /home/ tries to read /etc/hosts", func() {
			policyPath := "res/hsp-audit-hosts-fromsource-home.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			_, err = RunHostCommand([]string{"cat", "/etc/hosts"})
			Expect(err).To(BeNil())

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-hosts-fromsource-home",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should audit udp network protocol", func() {
			policyPath := "res/hsp-audit-network-protocol.yaml"

			err := KarmorHostLogStart("policy", "Network")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			_, _ = RunHostCommand([]string{"echo", "test", "|", "nc", "-u", "127.0.0.1", "9999"})

			target := &protobuf.Alert{
				PolicyName: "hsp-audit-network-protocol",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block file read (/etc/passwd)", func() {
			policyPath := "res/hsp-block-file-etc-passwd.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"cat", "/etc/passwd"}, MatchRegexp(`(?i)permission denied`), false)

			target := &protobuf.Alert{
				PolicyName: "hsp-kubearmor-dev-file-path-block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block /usr/bin/curl execution", func() {
			policyPath := "res/hsp-block-process-curl.yaml"

			err := KarmorHostLogStart("policy", "Process")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"curl", "--version"}, MatchRegexp(`(?i)permission denied`), false)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-curl-exec",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block reading files under /etc recursively", func() {
			policyPath := "res/hsp-block-file-dir-etc.yaml"

			err := KarmorHostLogStart("policy", "File")
			Expect(err).To(BeNil())

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"cat", "/etc/passwd"}, MatchRegexp(`(?i)permission denied`), false)
			AssertHostCommand([]string{"cat", "/etc/hosts"}, MatchRegexp(`(?i)permission denied`), false)

			target := &protobuf.Alert{
				PolicyName: "hsp-block-file-dir",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block process execution (/usr/bin/ls)", func() {
			policyPath := "res/hsp-block-process-ls.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"ls", "-l"}, MatchRegexp(`(?i)permission denied`), false)

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block execution of binaries under /usr/bin directory recursively", func() {
			policyPath := "res/hsp-block-process-dir-bin.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			AssertHostCommand([]string{"ls", "-l"}, MatchRegexp(`(?i)permission denied`), false)

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("should block all apt commands", func() {
			policyPath := "res/hsp-block-process-apt-pattern.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			aptCommands := [][]string{
				{"apt", "update"},
				{"apt-get", "upgrade", "-y"},
				{"apt-cache", "search", "kubernetes"},
			}

			for _, cmd := range aptCommands {
				AssertHostCommand(cmd, MatchRegexp(`(?i)permission denied`), false)
			}

			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})
})
