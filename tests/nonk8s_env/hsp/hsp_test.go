// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package hsp

import (
	"os"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Non-k8s HSP tests", func() {

	AfterEach(func() {
		KarmorLogStop()
	})

	BeforeEach(func() {
		// Set the environment variable
		os.Setenv("KUBEARMOR_SERVICE", ":32767")
	})

	Describe("HSP file path block", func() {

		It("can block access to /etc/hostname on the host", func() {

			policyPath := "res/hsp-kubearmor-dev-file-path-block.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// Access the /etc/hostname file
			out, err := ExecCommandHost([]string{"bash", "-c", "cat /etc/hostname"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-path-block"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())

		})
	})

	Describe("HSP Process path block", func() {

		It("can block execution of diff command in host", func() {

			policyPath := "res/hsp-kubearmor-dev-proc-path-block.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "Process", "")
			Expect(err).To(BeNil())

			// call the diff command
			out, err := ExecCommandHost([]string{"bash", "-c", "diff --help"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	Describe("HSP dir block from source", func() {

		It("can allow access to everything except /etc/default/* from head", func() {

			policyPath := "res/hsp-kubearmor-dev-file-dir-block-fromSource.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// call the head command
			out, err := ExecCommandHost([]string{"bash", "-c", "head /etc/hostname"})
			Expect(err).To(BeNil())
			Expect(out).NotTo(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically("==", 0))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})

		It("can block access to /etc/default/* from head", func() {

			policyPath := "res/hsp-kubearmor-dev-file-dir-block-fromSource.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// call the head command
			out, err := ExecCommandHost([]string{"bash", "-c", "head /etc/default/useradd"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-dir-block-fromsource"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	Describe("HSP file audit", func() {

		It("can audit access to /etc/passwd", func() {

			policyPath := "res/hsp-kubearmor-dev-file-path-audit.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// try to access the /etc/passwd file
			out, err := ExecCommandHost([]string{"bash", "-c", "cat /etc/passwd"})
			Expect(err).To(BeNil())
			Expect(out).ToNot(MatchRegexp(".*Permission denied"))

			// check audit alerts
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-path-audit"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Audit"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	Describe("HSP path block from source", func() {

		It("It can block access to /etc/hostname from head", func() {

			policyPath := "res/hsp-kubearmor-dev-file-path-block-fromSource.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// try to access the /etc/hostname file from head
			out, err := ExecCommandHost([]string{"bash", "-c", "head /etc/hostname"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-path-block-fromsource"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	// Describe("HSP Process path block from source", func() {

	// 	It("can block date command from bash", func() {

	// 		policyPath := "res/hsp-kubearmor-dev-proc-path-block-fromSource.yaml"
	// 		err := SendPolicy("ADDED", policyPath)
	// 		Expect(err).To(BeNil())

	// 		// Start the karmor logs
	// 		err = KarmorLogStart("policy", "", "Process", "")
	// 		Expect(err).To(BeNil())

	// 		// call the date command from bash
	// 		out, err := ExecCommandHost([]string{"bash", "-c", "date"})
	// 		Expect(err).To(BeNil())
	// 		Expect(out).To(MatchRegexp(".*Permission denied"))

	// 		// // execute ls command from bash
	// 		// out2, err := ExecCommandHost([]string{"bash", "-c", "ls"})
	// 		// Expect(err).To(BeNil())
	// 		// Expect(out2).NotTo(MatchRegexp(".*Permission denied"))

	// 		// check policy violation alert
	// 		_, alerts, err := KarmorGetLogs(5*time.Second, 1)
	// 		Expect(err).To(BeNil())
	// 		Expect(len(alerts)).To(BeNumerically(">=", 1))
	// 		Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block-fromsource"))
	// 		Expect(alerts[0].Severity).To(Equal("5"))
	// 		Expect(alerts[0].Action).To(Equal("Block"))

	// 		// delete the policy
	// 		err = SendPolicy("DELETED", policyPath)
	// 		Expect(err).To(BeNil())
	// 	})
	// })

	Describe("HSP Process path block", func() {

		It("can block diff command", func() {

			policyPath := "res/hsp-kubearmor-dev-proc-path-block.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "Process", "")
			Expect(err).To(BeNil())

			// run diff command
			out, err := ExecCommandHost([]string{"bash", "-c", "diff"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	Describe("HSP Network path block", func() {

		It("can block access to UDP protocol from curl", func() {

			policyPath := "res/hsp-kubearmor-dev-udp-block.yaml"
			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// Start the karmor logs
			err = KarmorLogStart("policy", "", "Network", "")
			Expect(err).To(BeNil())

			// run diff command
			out, err := ExecCommandHost([]string{"bash", "-c", "curl google.com"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Could not resolve host: google.com"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-udp-block-curl"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})
})
