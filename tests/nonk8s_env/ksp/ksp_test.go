// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor
package ksp_test

import (
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	_, err := RunDockerCommand([]string{
		"compose", "-f", "res/wordpress_docker/compose.yaml", "up", "-d",
	})
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = AfterSuite(func() {
	_, err := RunDockerCommand([]string{"rm", "-f", "wordpress-mysql"})
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = Describe("KSP Test", func() {
	AfterEach(func() {
		KarmorLogStop()
		time.Sleep(time.Second)
	})

	It("can audit file access", func() {
		err := KarmorHostLogStart("policy", "File")
		Expect(err).To(BeNil())

		policyPath := "res/ksp-audit-file-access.yaml"

		err = SendPolicy("ADDED", policyPath)
		Expect(err).To(BeNil())

		_, err = RunDockerCommand([]string{
			"exec", "wordpress-mysql", "bash", "-c", "cat /etc/shadow",
		})
		Expect(err).To(BeNil())

		target := &protobuf.Alert{
			PolicyName: "ksp-audit-file-access",
			Action:     "Audit",
			Result:     "Passed",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, target)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())

		err = SendPolicy("DELETED", policyPath)
		Expect(err).To(BeNil())
	})

	It("can audit access to /bin/ dir", func() {
		err := KarmorHostLogStart("policy", "Process")
		Expect(err).To(BeNil())

		policyPath := "res/ksp-audit-exec-dir.yaml"

		err = SendPolicy("ADDED", policyPath)
		Expect(err).To(BeNil())

		_, err = RunDockerCommand([]string{
			"exec", "wordpress-mysql", "bash", "-c", "ls",
		})
		Expect(err).To(BeNil())

		target := &protobuf.Alert{
			PolicyName: "ksp-block-exec-dir",
			Action:     "Audit",
			Result:     "Passed",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, target)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())

		err = SendPolicy("DELETED", policyPath)
		Expect(err).To(BeNil())
	})

	It("can audit TCP protocol access using curl", func() {
		err := KarmorHostLogStart("policy", "Network")
		Expect(err).To(BeNil())

		policyPath := "res/ksp-audit-protocol-tcp.yaml"

		err = SendPolicy("ADDED", policyPath)
		Expect(err).To(BeNil())

		_, err = RunDockerCommand([]string{
			"exec", "wordpress-mysql", "bash", "-c", "curl --help",
		})
		Expect(err).To(BeNil())

		target := &protobuf.Alert{
			PolicyName: "ksp-audit-protocol-tcp",
			Action:     "Audit",
			Result:     "Passed",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, target)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())

		err = SendPolicy("DELETED", policyPath)
		Expect(err).To(BeNil())
	})

	It("can audit access to /tmp via pattern", func() {
		err := KarmorHostLogStart("policy", "File")
		Expect(err).To(BeNil())

		policyPath := "res/ksp-audit-file-pattern.yaml"

		err = SendPolicy("ADDED", policyPath)
		Expect(err).To(BeNil())

		_, err = RunDockerCommand([]string{
			"exec", "wordpress-mysql", "bash", "-c", "echo test > /tmp/karmor_test_file",
		})
		Expect(err).To(BeNil())

		target := &protobuf.Alert{
			PolicyName: "ksp-audit-file-pattern",
			Action:     "Audit",
			Result:     "Passed",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, target)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())

		err = SendPolicy("DELETED", policyPath)
		Expect(err).To(BeNil())
	})

	It("can audit apt process execution via pattern", func() {
		err := KarmorHostLogStart("policy", "Process")
		Expect(err).To(BeNil())

		policyPath := "res/ksp-audit-process-apt-pattern.yaml"

		err = SendPolicy("ADDED", policyPath)
		Expect(err).To(BeNil())

		_, err = RunDockerCommand([]string{
			"exec", "wordpress-mysql", "bash", "-c", "apt --help",
		})
		Expect(err).To(BeNil())

		target := &protobuf.Alert{
			PolicyName: "ksp-audit-process-apt-pattern",
			Action:     "Audit",
			Result:     "Passed",
		}

		res, err := KarmorGetTargetAlert(10*time.Second, target)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())

		err = SendPolicy("DELETED", policyPath)
		Expect(err).To(BeNil())
	})
})
