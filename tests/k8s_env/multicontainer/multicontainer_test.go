// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package multicontainer

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql app in multicontainer ns
	err := K8sApply([]string{"manifests/multicontainer-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all KSPs
	KspDeleteAll()
})

var _ = AfterSuite(func() {
	// delete wordpress-mysql app from multicontainer ns
	err := K8sDelete([]string{"manifests/multicontainer-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getMultiContainerPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "multicontainer", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Multicontainer", func() {
	var multicontainer string
	BeforeEach(func() {
		multicontainer = getMultiContainerPod("multicontainer-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		KspDeleteAll()
	})

	Describe("Policy Apply", func() {

		It("can block ls in container-1 only", func() {
			err := K8sApply([]string{"manifests/container-1-ls-block.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "multicontainer", "Process", multicontainer)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-1", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			expect := protobuf.Alert{
				PolicyName:    "container-1-block-ls",
				Severity:      "2",
				ContainerName: "container-1",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			//container-2 should run ls
			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

		})
		It("Can enforce on all containers with empty array", func() {
			err := K8sApply([]string{"manifests/empty-array-ls-block.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "multicontainer", "Process", multicontainer)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-1", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect := protobuf.Alert{
				PolicyName:    "empty-array-ls-block",
				Severity:      "4",
				ContainerName: "container-1",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect = protobuf.Alert{
				PolicyName:    "empty-array-ls-block",
				Severity:      "4",
				ContainerName: "container-2",
			}

			// check policy violation alert
			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		//kubearmor.io/container.name: ""
		It("Can enforce on all containers with no array in labels", func() {
			err := K8sApply([]string{"manifests/empty-label-ls-block.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "multicontainer", "Process", multicontainer)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-1", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect := protobuf.Alert{
				PolicyName:    "empty-array-ls-block",
				Severity:      "4",
				ContainerName: "container-1",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect = protobuf.Alert{
				PolicyName:    "empty-array-ls-block",
				Severity:      "4",
				ContainerName: "container-2",
			}

			// check policy violation alert
			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("Can enforce on container-1 with malformated array", func() {
			err := K8sApply([]string{"manifests/malformated-array-ls-block.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "multicontainer", "Process", multicontainer)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-1", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			expect := protobuf.Alert{
				PolicyName:    "malformated-array-ls-block",
				Severity:      "4",
				ContainerName: "container-1",
			}

			// check policy violation alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			//container-2 should run ls
			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

		})
	})

})
