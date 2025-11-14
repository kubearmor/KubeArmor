// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package cronjobjobpod

import (
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	err := K8sApply([]string{"res/job-cronjob-pod.yaml"})
	Expect(err).To(BeNil())

	time.Sleep(30 * time.Second)

	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	err := K8sDelete([]string{"res/job-cronjob-pod.yaml"})
	Expect(err).To(BeNil())
})

func getPod(ns, prefix string) string {
	pods, err := K8sGetPods(prefix, ns, []string{"kubearmor-policy: enabled"}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("KubeArmor Pod/Job/CronJob Policy Tests", func() {
	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		time.Sleep(5 * time.Second)
	})

	It("should enforce file policy on Job", func() {
		err := K8sApplyFile("res/ksp-job-block.yaml")
		Expect(err).To(BeNil())
		time.Sleep(5 * time.Second)

		jobPod := getPod("ksp-test", "sample-job")
		err = KarmorLogStart("policy", "ksp-test", "File", jobPod)
		Expect(err).To(BeNil())

		AssertCommand(
			jobPod, "ksp-test", []string{"cat", "/etc/shadow"},
			MatchRegexp(".*"), true,
		)

		AssertCommand(
			jobPod, "ksp-test", []string{"cat", "/etc/hosts"},
			MatchRegexp("Permission denied"), true,
		)

		expect := protobuf.Alert{
			PolicyName: "ksp-job-block",
			Action:     "Block",
			Result:     "Permission denied",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, &expect)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())
	})

	It("should enforce file policy on CronJob", func() {
		// Ensuring no old job with the same name exists
		_, _ = Kubectl("delete job manual-cronjob-run -n ksp-test --ignore-not-found")

		// Manually trigger the CronJob
		_, err := Kubectl("create job --from=cronjob/sample-cronjob manual-cronjob-run -n ksp-test")
		Expect(err).To(BeNil())

		err = K8sApplyFile("res/ksp-cronjob-block.yaml")
		Expect(err).To(BeNil())

		time.Sleep(15 * time.Second)

		cronPod := getPod("ksp-test", "manual-cronjob-run")
		err = KarmorLogStart("policy", "ksp-test", "File", cronPod)
		Expect(err).To(BeNil())

		AssertCommand(
			cronPod, "ksp-test", []string{"cat", "/etc/shadow"},
			MatchRegexp(".*"), true,
		)

		AssertCommand(
			cronPod, "ksp-test", []string{"cat", "/etc/hosts"},
			MatchRegexp("Permission denied"), true,
		)

		expect := protobuf.Alert{
			PolicyName: "ksp-cronjob-block",
			Action:     "Block",
			Result:     "Permission denied",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, &expect)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())
	})

	It("should enforce file policy on Pod", func() {
		err := K8sApply([]string{"res/ksp-pod-block.yaml"})
		Expect(err).To(BeNil())
		time.Sleep(5 * time.Second)

		err = KarmorLogStart("policy", "ksp-test", "File", "sample-pod")
		Expect(err).To(BeNil())

		AssertCommand(
			"sample-pod", "ksp-test",
			[]string{"cat", "/etc/hostname"},
			MatchRegexp(".*"), true,
		)

		AssertCommand(
			"sample-pod", "ksp-test",
			[]string{"cat", "/etc/hosts"},
			MatchRegexp("Permission denied"), true,
		)

		expect := protobuf.Alert{
			PolicyName: "ksp-pod-block",
			Action:     "Block",
			Result:     "Permission denied",
		}

		res, err := KarmorGetTargetAlert(5*time.Second, &expect)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())
	})

})
