// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package multicontainer

import (
	"fmt"
	"time"

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

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("container-1-block-ls"))
			Expect(alerts[0].Severity).To(Equal("2"))
			Expect(alerts[0].ContainerName).To(Equal("container-1"))

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
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("empty-array-ls-block"))
			Expect(alerts[0].Severity).To(Equal("4"))
			Expect(alerts[0].ContainerName).To(Equal("container-1"))

			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err = KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("empty-array-ls-block"))
			Expect(alerts[0].Severity).To(Equal("4"))
			Expect(alerts[0].ContainerName).To(Equal("container-2"))

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
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("empty-array-ls-block"))
			Expect(alerts[0].Severity).To(Equal("4"))
			Expect(alerts[0].ContainerName).To(Equal("container-1"))

			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// check policy violation alert
			_, alerts, err = KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("empty-array-ls-block"))
			Expect(alerts[0].Severity).To(Equal("4"))
			Expect(alerts[0].ContainerName).To(Equal("container-2"))

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
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("malformated-array-ls-block"))
			Expect(alerts[0].Severity).To(Equal("4"))
			Expect(alerts[0].ContainerName).To(Equal("container-1"))

			//container-2 should run ls
			sout, _, err = K8sExecInPodWithContainer(multicontainer, "multicontainer", "container-2", []string{"bash", "-c", "ls"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

		})
	})

})
