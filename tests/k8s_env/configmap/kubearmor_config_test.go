// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package configmap

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// deploy ubuntu app
	err := K8sApplyFile("manifests/ubuntu-deployment.yaml")
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	cm := NewDefaultConfigMapData()
	cm.DefaultFilePosture = "block"
	cm.DefaultCapabilitiesPosture = "block"
	cm.DefaultNetworkPosture = "block"
	cm.Visibility = "process,file,network,capabilities"
	cm.CreateKAConfigMap()
	DeleteKAConfigMap()

	// these deployments are not needed after this suite
	err := K8sDelete([]string{"manifests/ubuntu-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getUnannotatedPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "unannotated", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

func getFullyAnnotatedPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "fullyannotated", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

func getPartialyAnnotatedPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "partialyannotated", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("KubeArmor-Config", func() {
	var unannotated string
	var partialyAnnotated string
	var fullyAnnotated string
	BeforeEach(func() {
		unannotated = getUnannotatedPod("unannotated-", "kubearmor-policy: enabled")
		partialyAnnotated = getPartialyAnnotatedPod("partialyannotated-", "kubearmor-policy: enabled")
		fullyAnnotated = getFullyAnnotatedPod("fullyannotated-", "kubearmor-policy: enabled")
		cm := NewDefaultConfigMapData()
		cm.CreateKAConfigMap()
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
	})

	Describe("Unannotated", func() {

		It("visibility will be set to configmap's value", Label("unannotated"), func() {
			// default global visibility is none
			cm := NewDefaultConfigMapData()
			err := cm.CreateKAConfigMap()
			Expect(err).To(BeNil())

			// wait for visibility maps to be updated in kernel, added due to flaky behaviour
			time.Sleep(5 * time.Second)

			err = KarmorLogStart("all", "unannotated", "", unannotated)
			Expect(err).To(BeNil())

			// this won't return anything
			sout, _, err := K8sExecInPodWithContainer(unannotated, "unannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)

			// check for audit logs, we shouldn't get any
			logs, _, err := KarmorGetLogs(5*time.Second, 50)
			Expect(err).To(BeNil())
			Expect(len(logs)).To(Equal(0))

			// update global visibility to file
			cm.Visibility = "file"
			err = cm.CreateKAConfigMap()
			Expect(err).To(BeNil())

			// wait for visibility maps to be updated in kernel, added due to flaky behaviour
			time.Sleep(5 * time.Second)

			err = KarmorLogStart("all", "unannotated", "", unannotated)
			Expect(err).To(BeNil())

			// file event
			sout, _, err = K8sExecInPodWithContainer(unannotated, "unannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)

			// check for logs, we should get logs for file events
			logs, _, err = KarmorGetLogs(5*time.Second, 50)
			Expect(err).To(BeNil())
			Expect(len(logs)).NotTo(Equal(0))

			expected := []string{
				"file",
			}
			operations := GetOperations(logs)

			Expect(IsOperationsExpected(operations, expected)).To(BeTrue())

		})

		It("default posture will be set to global posture configs", Label("unannotated"), func() {
			// apply a allow based policy
			err := K8sApplyFile("manifests/ksp-unannotated-allow.yaml")
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "unannotated", "File", unannotated)
			Expect(err).To(BeNil())

			// initialy global defaults posture is audit
			sout, _, err := K8sExecInPodWithContainer(unannotated, "unannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

			// change global default posture to block using configmap
			cm := NewDefaultConfigMapData()
			cm.DefaultFilePosture = "block"
			cm.DefaultCapabilitiesPosture = "block"
			cm.DefaultNetworkPosture = "block"
			err = cm.CreateKAConfigMap() // will create a configMap with default posture as block
			Expect(err).To(BeNil())

			// wait for policy updation due to defaultPosture change
			time.Sleep(5 * time.Second)

			// now defaults posture should be changed to block
			sout, _, err = K8sExecInPodWithContainer(unannotated, "unannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

		})
	})

	Describe("Partialy Annotated", Label("partial"), func() {

		It("default posture will be set to global config posture for unannotated posture only", func() {

			// apply a allow based policy
			err := K8sApplyFile("manifests/ksp-partialyAnnotated-allow.yaml")
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "partialyannotated", "File", partialyAnnotated)
			Expect(err).To(BeNil())

			// initialy namespace defaults posture (annotated) is audit for File
			sout, _, err := K8sExecInPodWithContainer(partialyAnnotated, "partialyannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

			// should get an alert with success
			// check policy violation alert

			target := protobuf.Alert{
				PolicyName:    "DefaultPosture",
				Action:        "Audit",
				Result:        "Passed",
				NamespaceName: "partialyannotated",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// change global default posture to block using configmap
			cm := NewDefaultConfigMapData()
			cm.DefaultFilePosture = "block"
			cm.DefaultCapabilitiesPosture = "block"
			cm.DefaultNetworkPosture = "block"
			err = cm.CreateKAConfigMap() // will create a configMap with default posture as block
			Expect(err).To(BeNil())

			// wait for policy updation due to defaultPosture change
			time.Sleep(5 * time.Second)

			err = KarmorLogStart("policy", "partialyannotated", "File", partialyAnnotated)
			Expect(err).To(BeNil())

			// defaults posture should still be audit for File
			sout, _, err = K8sExecInPodWithContainer(partialyAnnotated, "partialyannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).NotTo(MatchRegexp(".*Permission denied"))

		})
	})

	Describe("Fully Annotated", Label("full"), func() {

		It("visibility will default to ns annotation's value", Label("full"), func() {
			// default global visibility is none
			cm := NewDefaultConfigMapData()
			err := cm.CreateKAConfigMap()
			Expect(err).To(BeNil())

			err = KarmorLogStart("all", "fullyannotated", "", fullyAnnotated)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(fullyAnnotated, "fullyannotated", "ubuntu-1", []string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)

			// check for audit logs, we should get all
			logs, _, err := KarmorGetLogs(5*time.Second, 50)
			Expect(err).To(BeNil())
			Expect(len(logs)).NotTo(Equal(0))

			expected := []string{
				"file",
				"process",
				"syscall",
				"network",
			}
			operations := GetOperations(logs)

			Expect(IsOperationsExpected(operations, expected)).To(BeTrue())

		})

		It("default posture will be unchanged after global configs changed", func() {

			// apply a allow based policy
			err := K8sApplyFile("manifests/ksp-fullyAnnotated-allow.yaml")
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "fullyannotated", "Network", fullyAnnotated)
			Expect(err).To(BeNil())

			// initialy namespace defaults posture is block (annotated fully)
			sout, _, err := K8sExecInPodWithContainer(fullyAnnotated, "fullyannotated", "ubuntu-1", []string{"bash", "-c", "curl google.com"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*has moved"))

			// should get an alert with success
			// check policy violation alert

			target := protobuf.Alert{
				PolicyName:    "DefaultPosture",
				Action:        "Audit",
				Result:        "Passed",
				NamespaceName: "fullyannotated",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &target)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// change global default posture to block using configmap
			cm := NewDefaultConfigMapData()
			cm.DefaultFilePosture = "block"
			cm.DefaultCapabilitiesPosture = "block"
			cm.DefaultNetworkPosture = "block"
			err = cm.CreateKAConfigMap() // will create a configMap with default posture as block
			Expect(err).To(BeNil())

			// wait for policy updation due to defaultPosture change
			time.Sleep(5 * time.Second)

			// defaults posture should still be audit for network
			sout, _, err = K8sExecInPodWithContainer(fullyAnnotated, "fullyannotated", "ubuntu-1", []string{"bash", "-c", "curl google.com"})
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			Expect(sout).To(MatchRegexp(".*has moved"))

		})

		It("respects DropResourceFromProcessLogs flag", func() {
			// DropResourceFromProcessLogs is disabled (false) by default
			cm := NewDefaultConfigMapData()
			cm.Visibility = "process"
			err := cm.CreateKAConfigMap()
			Expect(err).To(BeNil())

			// Wait for config to update
			time.Sleep(5 * time.Second)

			// Start logging for process events
			err = KarmorLogStart("all", "fullyannotated", "Process", fullyAnnotated)
			Expect(err).To(BeNil())

			// Execute a process in the pod
			K8sExecInPodWithContainer(fullyAnnotated, "fullyannotated", "ubuntu-1", []string{"bash", "-c", "ps"})
			Expect(err).To(BeNil())

			// Get process logs
			logs, _, err := KarmorGetLogs(5*time.Second, 50)
			Expect(err).To(BeNil())
			Expect(len(logs)).NotTo(Equal(0))

			// Confirm Resource field is present in logs
			fmt.Printf("got logs: %+v", logs)
			for _, log := range logs {
				Expect(log.Resource).NotTo(Equal(""))
			}

			// now test with DropResourceFromProcessLogs enabled
			cm = NewDefaultConfigMapData()
			cm.Visibility = "process"
			cm.DropResourceFromProcessLogs = "true"
			err = cm.CreateKAConfigMap()
			Expect(err).To(BeNil())

			// Wait for config to update
			time.Sleep(5 * time.Second)

			// Stop and start logs to drain queue
			KarmorLogStop()
			err = KarmorLogStart("all", "fullyannotated", "Process", fullyAnnotated)
			Expect(err).To(BeNil())

			// Execute a process in the pod
			K8sExecInPodWithContainer(fullyAnnotated, "fullyannotated", "ubuntu-1", []string{"bash", "-c", "ps"})
			Expect(err).To(BeNil())

			// Get process logs
			logs, _, err = KarmorGetLogs(5*time.Second, 50)
			Expect(err).To(BeNil())
			Expect(len(logs)).NotTo(Equal(0))

			// Confirm Resource field is dropped in logs
			fmt.Printf("got logs: %+v", logs)
			for _, log := range logs {
				Expect(log.Resource).To(Equal(""))
			}
		})
	})

})
