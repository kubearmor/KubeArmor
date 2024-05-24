// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
package smoke_test

import (
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql deployment
	_, err := RunDockerCommand("compose -f res/wordpress_docker/compose.yaml up -d")
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = AfterSuite(func() {

	// remove policy
	policyPath := "res/ksp-wordpress-block-policy.yaml"
	err := SendPolicy("DELETED", policyPath)
	Expect(err).To(BeNil())

	// delete wordpress-mysql app
	_, err = RunDockerCommand("rm -f wordpress-mysql")
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = Describe("Systemd", func() {

	Describe(" Apply and Delete Policy ", func() {

		It(" It can add policy successfully ", func() {
			policyPath := "res/ksp-wordpress-block-policy.yaml"

			err := SendPolicy("ADDED", policyPath)

			Expect(err).To(BeNil())
		})
		It("It can delete policy", func() {

			policyPath := "res/ksp-wordpress-block-policy.yaml"

			err := SendPolicy("DELETED", policyPath)

			Expect(err).To(BeNil())
		})
	})

	Describe(" It can receive policy and container info ", func() {

		It(" It can receive updated container list through grpc ", func() {

			resp, err := ContainerInfo()
			Expect(err).To(BeNil())

			contains := false
			for _, containerName := range resp.ContainerList {
				if containerName == "wordpress-mysql" {
					contains = true
					break
				}
			}
			Expect(contains).To(BeTrue())

			// Deleting the container and then checking if the list is updated or not
			_, err = RunDockerCommand("rm -f wordpress-mysql")
			Expect(err).To(BeNil())

			resp, err = ContainerInfo()
			Expect(err).To(BeNil())
			contains = false
			for _, containerName := range resp.ContainerList {
				if containerName == "wordpress-mysql" {
					contains = true
					break
				}
			}
			Expect(contains).To(BeFalse())

		})
		It(" It can receive updated policy list through grpc ", func() {
			_, err := RunDockerCommand("compose -f res/wordpress_docker/compose.yaml up -d")
			Expect(err).To(BeNil())
			time.Sleep(5 * time.Second)
			// No policy is applied right now
			resp, err := ContainerInfo()
			Expect(err).To(BeNil())

			listLength := len(resp.ContainerMap["wordpress-mysql"].PolicyList)
			Expect(listLength).To(Equal(0))

			// With policy applied

			policyPath := "res/ksp-wordpress-block-policy.yaml"

			err = SendPolicy("ADDED", policyPath)

			Expect(err).To(BeNil())

			resp, err = ContainerInfo()
			Expect(err).To(BeNil())

			listLength = len(resp.ContainerMap["wordpress-mysql"].PolicyList)
			Expect(listLength).To(Equal(1))

		})
	})

	Describe(" It can block apt and apt-get commands in container ", func() {

		It(" It can block apt command inside the container ", func() {

			// Start the karmor logs
			err := KarmorLogStartgRPC("policy", "", "Process", "", ":32767")
			Expect(err).To(BeNil())

			// out, err := ExecInDockerContainer("wordpress-mysql", []string{"bash", "-c", "apt update"})
			out, _ := RunDockerCommand("exec wordpress-mysql apt update")
			// Since the apt command won't run, it will return an error
			// Expect(err).NotTo(BeNil())
			Expect(out).To(MatchRegexp(".*permission denied"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("ksp-block-policy"))
			Expect(alerts[0].Severity).To(Equal("3"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})
	})

})
