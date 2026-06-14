// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package deep_path

import (
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	deepPathNS     = "deep-path"
	deepDir        = "/tmp/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u"
	deepBinary     = deepDir + "/test_shell"
	shallowBinary  = "/tmp/shallow/test_shell"
	setupScript    = "mkdir -p /tmp/shallow " + deepDir + " && cp /bin/bash " + shallowBinary + " && cp /bin/bash " + deepBinary + " && chmod +x " + shallowBinary + " " + deepBinary
)

var _ = BeforeSuite(func() {
	err := K8sApply([]string{"res/deep-path-deployment.yaml"})
	Expect(err).To(BeNil())

	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	err := K8sDelete([]string{"res/deep-path-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getDeepPathPod() string {
	pods, err := K8sGetPods("deep-path-", deepPathNS, []string{"kubearmor-policy: enabled"}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("DeepPath", func() {
	var pod string

	BeforeEach(func() {
		if !strings.Contains(K8sRuntimeEnforcer(), "bpf") {
			Skip("Skipping due to BPF-LSM-only prepend_path enforcement fix")
		}

		pod = getDeepPathPod()
		AssertCommand(pod, deepPathNS, []string{"bash", "-c", setupScript}, MatchRegexp(".*"), true)
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		time.Sleep(5 * time.Second)
	})

	It("blocks execution of a shallow resolvable path with a Block policy (regression)", func() {
		err := K8sApplyFile("res/ksp-shallow-block.yaml")
		Expect(err).To(BeNil())

		err = KarmorLogStart("policy", deepPathNS, "Process", pod)
		Expect(err).To(BeNil())

		time.Sleep(5 * time.Second)

		AssertCommand(pod, deepPathNS, []string{shallowBinary, "--version"},
			MatchRegexp("Permission denied"), true)

		expect := protobuf.Alert{
			PolicyName: "ksp-shallow-block",
			Action:     "Block",
			Result:     "Permission denied",
		}

		res, err := KarmorGetTargetAlert(10*time.Second, &expect)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())
	})

	It("blocks execution of a path deeper than the dentry-walk cap (issue #2609)", func() {
		err := K8sApplyFile("res/ksp-deep-block.yaml")
		Expect(err).To(BeNil())

		err = KarmorLogStart("policy", deepPathNS, "Process", pod)
		Expect(err).To(BeNil())

		time.Sleep(5 * time.Second)

		AssertCommand(pod, deepPathNS, []string{deepBinary, "--version"},
			MatchRegexp("Permission denied"), true)

		expect := protobuf.Alert{
			Result: "Permission denied",
		}

		res, err := KarmorGetTargetAlert(10*time.Second, &expect)
		Expect(err).To(BeNil())
		Expect(res.Found).To(BeTrue())
	})

	It("does not block resolvable unrelated binaries", func() {
		err := K8sApplyFile("res/ksp-deep-block.yaml")
		Expect(err).To(BeNil())

		err = KarmorLogStart("policy", deepPathNS, "Process", pod)
		Expect(err).To(BeNil())

		time.Sleep(5 * time.Second)

		AssertCommand(pod, deepPathNS, []string{"/bin/true"}, MatchRegexp("^$"), false)
	})
})
