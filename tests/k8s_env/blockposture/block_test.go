// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package blockposture

import (
	"time"

	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// deploy nginx app
	err := K8sApply([]string{"res/nginx-posture-deployment.yaml"})
	Expect(err).To(BeNil())
	//annotate block posture on namespace level
	_, err = Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
	Expect(err).To(BeNil())

	_, err = Kubectl("annotate ns nginx-posture kubearmor-file-posture=block --overwrite")
	Expect(err).To(BeNil())

	//give some time for the deployment to be up before applying whitelisting policies
	time.Sleep(60 * time.Second)
	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// delete nginx app
	err := K8sDelete([]string{"res/nginx-posture-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getNginxPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "nginx-posture", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Posture", func() {

	var ng string

	BeforeEach(func() {
		ng = getNginxPod("nginx-posture-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can whitelist certain files accessed by a package while blocking all other sensitive content", func() {
			err := util.AnnotateNS("nginx-posture", "kubearmor-file-posture", "block")
			Expect(err).To(BeNil())
			// Apply policy
			err = K8sApplyFile("res/ksp-nginx-allow-file.yaml")
			Expect(err).To(BeNil())

			// wait for policy creation, added due to flaky behaviour
			time.Sleep(10 * time.Second)

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx-posture", "File", ng)
			Expect(err).To(BeNil())

			AssertCommand(
				ng, "nginx-posture", []string{"sh", "-c", "cat docker-entrypoint.sh"},
				MatchRegexp("cat.*Permission denied"), true,
			)

			AssertCommand(
				ng, "nginx-posture", []string{"sh", "-c", "cat /usr/share/nginx/html/index.html"},
				MatchRegexp("<!DOCTYPE html>((?:.*\r?\n?)*)</html>"), true,
			)
			// check policy violation alert
			_, alerts, err := KarmorGetLogs(10*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})
	})

})
