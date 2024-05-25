package hsp

import (
	"fmt"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {

	// delete all HSPs
	DeleteAllHsp()
})

var _ = AfterSuite(func() {

	// delete all HSPs
	DeleteAllHsp()
})

var _ = Describe("HSP", func() {

	BeforeEach(func() {
		time.Sleep(1 * time.Second)
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllHsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(2 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can block access to date command", func() {
			// Apply the Host Security Policy
			err := K8sApplyFile("manifests/hsp-kubearmor-dev-proc-path-block.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "", "Process", "")
			Expect(err).To(BeNil())

			// Execute the date command
			out, err := ExecCommandHost([]string{"bash", "-c", "date"})
			Expect(err).NotTo(BeNil())
			fmt.Printf("---START---\n%s---END---\n", out)
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block"))
			Expect(alerts[0].Action).To(Equal("Block"))

			// Execute a command that should not be blocked
			out, err = ExecCommandHost([]string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			Expect(out).NotTo(MatchRegexp(".*Permission denied"))
		})

		It("can block access to /etc/hostname file", func() {
			// Apply the Host Security Policy
			err := K8sApplyFile("manifests/hsp-kubearmor-dev-file-path-block.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "", "File", "")
			Expect(err).To(BeNil())

			// Try to access the /etc/hostname file
			out, err := ExecCommandHost([]string{"bash", "-c", "cat /etc/hostname"})
			Expect(err).NotTo(BeNil())
			fmt.Printf("---START---\n%s---END---\n", out)
			Expect(out).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-file-path-block"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})
	})
})
