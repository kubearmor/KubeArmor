// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package smoke

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/karts/util"
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

	// enable kubearmor port forwarding
	err = KubearmorPortForward()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	KubearmorPortForwardStop()
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
		wp = getWpsqlPod("wordpress-",
			"container.apparmor.security.beta.kubernetes.io/wordpress: localhost/kubearmor-wordpress-mysql-wordpress-wordpress")
		sql = getWpsqlPod("mysql-",
			"container.apparmor.security.beta.kubernetes.io/mysql: localhost/kubearmor-wordpress-mysql-mysql-mysql")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
	})

	Describe("Policy Apply", func() {
		It("can block execution of pkg mgmt tools such as apt, apt-get", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-process.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "Process", wp)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wp, "wordpress-mysql", []string{"bash", "-c", "apt"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp("apt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-wordpress-block-process",
				Severity:   "3",
				Action:     "Block",
				Result:     "Permission denied",
			}

			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of access to sensitive file with abs path", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-config.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /var/www/html/wp-config.php"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("wp-config.php.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-wordpress-block-config",
				Message:    "blocked access to wordpress configuration file",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of access to sensitive file with rel path", func() {
			Skip("Check https://github.com/kubearmor/KubeArmor/issues/750")
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-config.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat wp-config.php"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("wp-config.php.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-wordpress-block-process",
				Severity:   "10",
				Message:    "blocked access to wordpress configuration file",
				Action:     "Block",
				Result:     "Permission denied",
			}
			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of access to service account token", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-block-sa.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("token.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-wordpress-block-sa",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}
			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("allow access for service account token to only cat", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-lenient-allow-sa.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			// trigger policy violation alert
			sout, _, err := K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "head /run/secrets/kubernetes.io/serviceaccount/token"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("token.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-wordpress-lenient-allow-sa",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}
			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// trigger normal operations permitted by policy
			sout, _, err = K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"})
			Expect(err).To(BeNil())
			Expect(sout).To(Not(ContainSubstring("Permission denied")))

			sout, _, err = K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "cat /etc/passwd"})
			Expect(err).To(BeNil())
			Expect(sout).To(Not(ContainSubstring("Permission denied")))

			sout, _, err = K8sExecInPod(wp, "wordpress-mysql",
				[]string{"bash", "-c", "head /etc/passwd"})
			Expect(err).To(BeNil())
			Expect(sout).To(Not(ContainSubstring("Permission denied")))

			// check policy violation alert
			res, err = KarmorGetAlert(5*time.Second, protobuf.Alert{})
			Expect(err).To(BeNil())
			Expect(len(res.Alerts)).To(BeNumerically("==", 0))
		})

		It("can audit access to sensitive data path", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-mysql-audit-dir.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", sql)
			Expect(err).To(BeNil())

			fname := fmt.Sprintf("/var/lib/mysql/%s", RandString(12))
			sout, _, err := K8sExecInPod(sql, "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("touch %s", fname)})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "ksp-mysql-audit-dir",
				Severity:   "5",
				Action:     "Audit",
				Result:     "Passed",
			}
			// check policy violation alert
			res, err := KarmorGetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			_, _, err = K8sExecInPod(sql, "wordpress-mysql",
				[]string{"bash", "-c", fmt.Sprintf("rm %s", fname)})
			Expect(err).To(BeNil())
		})
	})

})
