package hsp

import (
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Non-k8s HSP tests", func() {

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllHsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		// time.Sleep(2 * time.Second)
	})

	Describe("HSP file path block", func() {

		It("can block access to /etc/hostname on the host", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-file-path-block.yaml")
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

		})
	})

	Describe("HSP Process path block", func() {

		It("can block execution of diff command in host", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-proc-path-block.yaml")
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
		})
	})

	Describe("HSP dir block from source", func() {

		It("can allow access to everything except /etc/default/* from head", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-file-dir-block-fromSource.yaml")
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
		})

		It("can block access to /etc/default/* from head", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-file-dir-block-fromSource.yaml")
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
		})
	})

	Describe("HSP file audit", func() {

		It("can audit access to /etc/passwd", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-file-path-audit.yaml")
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
		})
	})

	Describe("HSP path block from source", func() {

		It("It can block access to /etc/hostname from head", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-file-path-block-fromSource.yaml")
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
		})
	})

	// Describe("HSP Process path block from source", func() {

	// 	FIt("can block date command from bash", func() {

	// 		err := K8sApplyFile("res/hsp-kubearmor-dev-proc-path-block-fromSource.yaml")
	// 		Expect(err).To(BeNil())

	// 		// Start the karmor logs
	// 		err = KarmorLogStart("policy", "", "Process", "")
	// 		Expect(err).To(BeNil())

	// 		// call the date command from bash
	// 		out, err := ExecCommandHost([]string{"bash", "-c", "date"})
	// 		Expect(err).To(BeNil())
	// 		Expect(out).To(MatchRegexp(".*Permission denied"))

	// 		// execute ls command from bash
	// 		out2, err := ExecCommandHost([]string{"bash", "-c", "ls"})
	// 		Expect(err).To(BeNil())
	// 		Expect(out2).NotTo(MatchRegexp(".*Permission denied"))

	// 		// check policy violation alert
	// 		_, alerts, err := KarmorGetLogs(5*time.Second, 1)
	// 		Expect(err).To(BeNil())
	// 		Expect(len(alerts)).To(BeNumerically(">=", 1))
	// 		Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-proc-path-block-fromsource"))
	// 		Expect(alerts[0].Severity).To(Equal("5"))
	// 		Expect(alerts[0].Action).To(Equal("Block"))
	// 	})
	// })

	Describe("HSP Process path block", func() {

		It("can block diff command", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-proc-path-block.yaml")
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
		})
	})

	Describe("HSP Network path block", func() {

		It("can block access to UDP protocol from curl", func() {

			err := K8sApplyFile("res/hsp-kubearmor-dev-udp-block.yaml")
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
		})
	})
})
