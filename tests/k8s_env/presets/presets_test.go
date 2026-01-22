// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package presets

import (
	"fmt"
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql app
	err := K8sApply([]string{"res/python-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// Delete wordpress-mysql app
	err := K8sDelete([]string{"res/python-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getfilelessPod(name string, ant []string) string {
	pods, err := K8sGetPods(name, "presets", ant, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Presets", func() {
	var fp string

	BeforeEach(func() {
		fp = getfilelessPod("fileless-", []string{"kubearmor-policy: enabled"})
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can audit fileless execution", func() {
			if !strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("fileless execution preset requires bpf-lsm")
			}
			// Apply policy
			err := K8sApplyFile("res/ksp-preset-audit-fileless.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "presets", "Process", fp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			sout, _, err := K8sExecInPod(fp, "presets", []string{"sh", "-c", "python3 ls.py"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(Not(ContainSubstring("Permission denied")))

			// check policy violation alert
			expect := protobuf.Alert{
				PolicyName: "ksp-preset-audit-fileless",
				Result:     "Passed",
				// Severity:   "8",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block fileless execution", func() {
			if !strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("fileless execution preset requires bpf-lsm")
			}
			// Apply policy
			err := K8sApplyFile("res/ksp-preset-block-fileless.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "presets", "Process", fp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			sout, _, err := K8sExecInPod(fp, "presets", []string{"sh", "-c", "python3 ls.py"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect := protobuf.Alert{
				PolicyName: "ksp-preset-block-fileless",
				Result:     "Permission denied",
				// Severity:   "8",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})
})
