// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package smoke

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql app
	err := K8sApply([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// Delete wordpress-mysql app
	err := K8sDelete([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getWpsqlPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "wordpress-mysql", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Smoke", func() {
	var wp string
	var sql string

	BeforeEach(func() {
		wp = getWpsqlPod("wordpress-", "kubearmor-policy: enabled")
		sql = getWpsqlPod("mysql-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can block execution of pkg mgmt tools such as apt, apt-get", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-process.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "Process", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"),
				false)

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-process"))
			Expect(alerts[0].Severity).To(Equal("3"))
		})

		It("can block execution of access to sensitive file with abs path", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-config.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /var/www/html/wp-config.php"},
				MatchRegexp("wp-config.php.*Permission denied"),
				false)

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
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-config.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat wp-config.php"},
				MatchRegexp("wp-config.php.*Permission denied"),
				false)

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
			err := K8sApplyFile("res/ksp-wordpress-block-sa.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand("wp-pod-name", "wordpress-mysql",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"},
				MatchRegexp("token.*Permission denied"),
				false)

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-sa"))
			Expect(alerts[0].Severity).To(Equal("7"))
		})

		It("allow access for service account token to only cat", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-lenient-allow-sa.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			// trigger policy violation alert
			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "head /run/secrets/kubernetes.io/serviceaccount/token"},
				MatchRegexp("token.*Permission denied"),
				false)
			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("---Alert---\n%s", alerts[0].String())
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-lenient-allow-sa"))
			Expect(alerts[0].Severity).To(Equal("7"))

			// trigger normal operations permitted by policy
			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"},
				Not(ContainSubstring("Permission denied")),
				false)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /etc/passwd"},
				Not(ContainSubstring("Permission denied")),
				false)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "head /etc/passwd"},
				Not(ContainSubstring("Permission denied")),
				false)

			// check for no policy violation alert
			_, alerts, err = KarmorGetLogs(3*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically("==", 0))
		})

		It("can audit access to sensitive data path", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-mysql-audit-dir.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", sql)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			fname := fmt.Sprintf("/var/lib/mysql/%s", RandString(12))
			AssertCommand(sql, "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("touch %s", fname)},
				MatchRegexp(".*"),
				false)

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("---Alert---\n%s", alerts[0].String())
			Expect(alerts[0].PolicyName).To(Equal("ksp-mysql-audit-dir"))
			Expect(alerts[0].Severity).To(Equal("5"))

			AssertCommand(sql, "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("rm %s", fname)},
				MatchRegexp(".*"),
				false)
		})

		It("can enforce multiple rules targeting same pod", func() {
			// Apply policy
			err := K8sApply([]string{"res/ksp-wordpress-two-policies.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", sql)
			Expect(err).To(BeNil())

			// trigger policy violation alert
			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /etc/passwd"},
				MatchRegexp("/etc/passwd.*Permission denied"),
				false)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /etc/shadow"},
				MatchRegexp("/etc/shadow.*Permission denied"),
				false)
		})

		It("can block write access and only allow read access to mounted files", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-mount-file.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "touch /dev/shm/new"},
				ContainSubstring("Permission denied"),
				false)

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(alerts[0].PolicyName).To(Equal("ksp-wordpress-block-mount-file"))
			Expect(alerts[0].Severity).To(Equal("5"))
		})
		It("will allow use of tcp network protocol by curl and bash", func() {
			err := util.AnnotateNS("wordpress-mysql", "kubearmor-network-posture", "audit")
			Expect(err).To(BeNil())
			// Apply policy
			err = K8sApplyFile("res/ksp-wordpress-allow-tcp.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "Network", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "curl 142.250.193.46"},
				ContainSubstring("http://www.google.com/"),
				false)

			// check alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			fmt.Printf("OUTPUT: %s\n", alerts)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(Equal(0))

			// tcp + udp + raw action
			AssertCommand(wp, "wordpress-mysql",
				[]string{"bash", "-c", "curl google.com"},
				ContainSubstring("http://www.google.com/"),
				false)
			// check alert
			_, alerts, err = KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Result).To(Equal("Passed"))
		})
	})
})
