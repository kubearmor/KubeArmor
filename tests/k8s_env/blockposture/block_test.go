// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package blockposture

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

	//annotate block posture on namespace level
	_, err = Kubectl(fmt.Sprintf("annotate ns wordpress-mysql kubearmor-network-posture=block --overwrite"))
	Expect(err).To(BeNil())

	_, err = Kubectl(fmt.Sprintf("annotate ns wordpress-mysql kubearmor-file-posture=block --overwrite"))
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// delete wordpress-mysql app
	err := K8sDelete([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getWpsqlPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "wordpress-mysql", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Posture", func() {
	var wp string
	// var sql string

	BeforeEach(func() {
		wp = getWpsqlPod("wordpress-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can whitelist use of certain network protocols used by a package, such as tcp", func() {
			// Apply policy
			err := K8sApplyFile("res/ksp-wordpress-allow-tcp.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "Network", wp)
			Expect(err).To(BeNil())

			AssertCommand(
				wp, "wordpress-mysql", []string{"bash", "-c", "curl google.com"},
				MatchRegexp("curl.*Could not resolve host: google.com"), true,
			)
			AssertCommand(
				wp, "wordpress-mysql", []string{"bash", "-c", "curl 142.250.193.46"}, 
				MatchRegexp("<HTML>((?:.*\r?\n?)*)</HTML>"), false,
			)
			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})

		It("can whitelist certain files accessed by a package while blocking all other sensitive content", func() {
			err := util.AnnotateNS("wordpress-mysql", "kubearmor-network-posture", "block")
			Expect(err).To(BeNil())
			// Apply policy
			err = K8sApplyFile("res/ksp-wordpress-allow-file.yaml")
			Expect(err).To(BeNil())

			// wait for policy creation, added due to flaky behaviour
			time.Sleep(5 * time.Second)

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "wordpress-mysql", "File", wp)
			Expect(err).To(BeNil())

			//curl needs UDP for DNS resolution
			AssertCommand(
				wp, "wordpress-mysql", []string{"bash", "-c", "cat wp-config.php"}, 
				MatchRegexp("cat.*Permission denied"), false,
			)
			//test that tcp is whitelisted
			AssertCommand(
				wp, "wordpress-mysql", []string{"bash", "-c", "cat readme.html"}, 
				MatchRegexp("<!DOCTYPE html>((?:.*\r?\n?)*)</html>"), false,
			)
			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})
	})

})
