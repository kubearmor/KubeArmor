// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package throttling

import (
	"fmt"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
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
})

var _ = AfterSuite(func() {
	// Delete wordpress-mysql app
	err := K8sDelete([]string{"res/wordpress-mysql-deployment.yaml"})
	Expect(err).To(BeNil())
	DeleteKAConfigMap()
})

func getWpsqlPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "wordpress-mysql", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Smoke", func() {
	var wp string

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

	Describe("Alert Throttling", func() {

		It("enabled with new throttling conditions", func() {
			// enable throttling and change throttling condition using configmap
			cm := NewDefaultConfigMapData()
			cm.AlertThrottling = "true"
			cm.MaxAlertPerSec = "2"
			cm.ThrottleSec = "60"
			cm.Visibility = "process,network,file,capabilities"
			err := cm.CreateKAConfigMap() // will create a configMap with new throttling condition
			Expect(err).To(BeNil())

			// Apply policy
			err = K8sApplyFile("res/ksp-wordpress-block-process.yaml")
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("all", "wordpress-mysql", "AlertThreshold", wp)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(15 * time.Second)

			AssertCommand(
				wp, "wordpress-mysql",
				[]string{"bash", "-c", "count=0; while [ $count -lt 5 ]; do apt; count=$((count + 1)); done;"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			fmt.Printf("throttling alert :%v\n", alerts)
			Expect(len(alerts)).ToNot(Equal(0))
			Expect(alerts[0].Type).To(Equal("SystemEvent"))
			Expect(alerts[0].Operation).To(Equal("AlertThreshold"))

			// Start Kubearmor Logs
			err = KarmorLogStart("all", "wordpress-mysql", "", wp)
			Expect(err).To(BeNil())

			// check for throttling, alerts should not be genrated
			AssertCommand(
				wp, "wordpress-mysql",
				[]string{"bash", "-c", "apt update"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			_, alerts, err = KarmorGetLogs(5*time.Second, 1)
			Expect(err).To(BeNil())
			fmt.Printf("throttling alert :%v\n", alerts)
			Expect(len(alerts)).To(BeNumerically("==", 0))
		})
	})
})
