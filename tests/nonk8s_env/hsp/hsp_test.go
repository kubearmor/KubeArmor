package hsp

import (
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Systemd HSP", func() {

	AfterEach(func() {
		KarmorLogStop()
	})

	Describe("HSP file path block", func() {

		It("It can block access to /etc/hostname on the host", func() {

			// Start the karmor logs
			err := KarmorLogStartgRPC("policy", "", "File", "", ":32767")
			Expect(err).To(BeNil())

			policyPath := "res/hsp-kubearmor-dev-file-path-block.yaml"
			err = SendPolicy("ADDED", policyPath)
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

	Describe("HSP Process block", func() {

		It("It can block execution of sleep command in host", func() {

			// Start the karmor logs
			err := KarmorLogStartgRPC("policy", "", "Process", "", ":32767")
			Expect(err).To(BeNil())

			policyPath := "res/hsp-kubearmor-dev-process-block.yaml"
			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			// call the sleep command
			out, err := ExecCommandHost([]string{"bash", "-c", "sleep 1"})
			Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-process-block"))
			Expect(alerts[0].Severity).To(Equal("5"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// delete the policy
			err = SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})
})
