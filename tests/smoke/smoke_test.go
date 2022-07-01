package smoke

import (
	"fmt"
	"time"

	. "github.com/kubearmor/karts/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql app
	err := K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all KSPs
	KspDeleteAll()

	// enable kubearmor port forwarding
	err = KubearmorPortForward()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	KubearmorPortForwardStop()
})

var _ = Describe("Smoke", func() {
	var wppods []string
	var sqlpods []string

	BeforeEach(func() {
		// Get wordpress pod
		pods, err := K8sGetPods("wordpress-", "wordpress-mysql", 20)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(Equal(1))
		wppods = pods

		// Get mysql pod
		pods, err = K8sGetPods("mysql-", "wordpress-mysql", 20)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(Equal(1))
		sqlpods = pods
	})

	AfterEach(func() {
		KarmorLogStop()
		KspDeleteAll()
	})

	Describe("Policy Apply", func() {
		It("can block execution of pkg mgmt tools such as apt, apt-get", func() {
			// Apply policy
			err := K8sApply([]string{"res/ksp-wordpress-block-process.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "Process", wppods[0])
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wppods[0], "wordpress-mysql", []string{"bash", "-c", "apt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("apt.*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-process"))
			Expect(alerts[0].Severity).To(Equal("3"))
		})

		It("can block execution of access to sensitive file with abs path", func() {
			// Apply policy
			err := K8sApply([]string{"res/ksp-wordpress-block-config.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wppods[0])
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wppods[0], "wordpress-mysql",
				[]string{"bash", "-c", "cat /var/www/html/wp-config.php"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("wp-config.php.*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("%+v\n", alerts[0])
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-config"))
			Expect(alerts[0].Severity).To(Equal("10"))
			Expect(alerts[0].Message).To(Equal("blocked access to wordpress configuration file"))
		})

		It("can block execution of access to sensitive file with rel path", func() {
			Skip("Check https://github.com/kubearmor/KubeArmor/issues/750")
			// Apply policy
			err := K8sApply([]string{"res/ksp-wordpress-block-config.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wppods[0])
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wppods[0], "wordpress-mysql",
				[]string{"bash", "-c", "cat wp-config.php"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("wp-config.php.*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("%+v\n", alerts[0])
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-config"))
			Expect(alerts[0].Severity).To(Equal("10"))
			Expect(alerts[0].Message).To(Equal("blocked access to wordpress configuration file"))
		})

		It("can block execution of access to service account token", func() {
			// Apply policy
			err := K8sApply([]string{"res/ksp-wordpress-block-sa.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wppods[0])
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wppods[0], "wordpress-mysql",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("token.*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-sa"))
			Expect(alerts[0].Severity).To(Equal("7"))
		})

		It("can audit access to sensitive data path", func() {
			// Apply policy
			err := K8sApply([]string{"res/ksp-mysql-audit-dir.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", sqlpods[0])
			Expect(err).To(BeNil())

			fname := fmt.Sprintf("/var/lib/mysql/%s", RandString(12))
			sout, _, err := K8sExecInPod(sqlpods[0], "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("touch %s", fname)})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			//			Expect(sout).To(MatchRegexp("token.*Permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-mysql-audit-dir"))
			Expect(alerts[0].Severity).To(Equal("5"))

			_, _, err = K8sExecInPod(sqlpods[0], "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("rm %s", fname)})
			Expect(err).To(BeNil())
		})
	})

})
