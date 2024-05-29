// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
package container_test

import (
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install nginx-redis deployment
	_, err := RunDockerCommand("compose -f res/nginx_docker/compose.yaml up -d")
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = AfterSuite(func() {
	// delete nginx-redis app
	_, err := RunDockerCommand("rm -f nginx redis")
	Expect(err).To(BeNil())

	time.Sleep(5 * time.Second)
})

var _ = Describe("Container Security Policy", func() {

	Describe("Apply and Delete Policy", func() {

		It("can add policy successfully", func() {
			policyPath := "res/container-block.yaml"

			err := SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())
		})
		It("can delete policy", func() {
			policyPath := "res/container-block.yaml"

			err := SendPolicy("DELETED", policyPath)
			Expect(err).To(BeNil())
		})
	})

	Describe("Policy and Container Info", func() {

		It("can receive updated container list through grpc", func() {
			resp, err := ContainerInfo()
			Expect(err).To(BeNil())

			containsNginx := false
			containsRedis := false
			for _, containerName := range resp.ContainerList {
				if containerName == "nginx" {
					containsNginx = true
				}
				if containerName == "redis" {
					containsRedis = true
				}
			}
			Expect(containsNginx).To(BeTrue())
			Expect(containsRedis).To(BeTrue())

			// Deleting the containers and then checking if the list is updated or not
			_, err = RunDockerCommand("rm -f nginx redis")
			Expect(err).To(BeNil())

			resp, err = ContainerInfo()
			Expect(err).To(BeNil())
			containsNginx = false
			containsRedis = false
			for _, containerName := range resp.ContainerList {
				if containerName == "nginx" {
					containsNginx = true
				}
				if containerName == "redis" {
					containsRedis = true
				}
			}
			Expect(containsNginx).To(BeFalse())
			Expect(containsRedis).To(BeFalse())
		})

		It("can receive updated policy list through grpc", func() {
			_, err := RunDockerCommand("compose -f res/nginx_docker/compose.yaml up -d")
			Expect(err).To(BeNil())
			time.Sleep(5 * time.Second)

			// No policy is applied right now
			resp, err := ContainerInfo()
			Expect(err).To(BeNil())

			nginxPolicyListLength := len(resp.ContainerMap["nginx"].PolicyList)
			redisPolicyListLength := len(resp.ContainerMap["redis"].PolicyList)
			Expect(nginxPolicyListLength).To(Equal(0))
			Expect(redisPolicyListLength).To(Equal(0))

			// With policy applied
			policyPath := "res/container-block.yaml"

			err = SendPolicy("ADDED", policyPath)
			Expect(err).To(BeNil())

			resp, err = ContainerInfo()
			Expect(err).To(BeNil())

			nginxPolicyListLength = len(resp.ContainerMap["nginx"].PolicyList)
			redisPolicyListLength = len(resp.ContainerMap["redis"].PolicyList)
			Expect(nginxPolicyListLength).To(Equal(1))
			Expect(redisPolicyListLength).To(Equal(1))
		})
	})
})
