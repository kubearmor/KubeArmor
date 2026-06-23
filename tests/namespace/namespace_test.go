// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package namespace

import (
	"fmt"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	err := K8sApply([]string{"res/ubuntu-deployment.yaml"})
	Expect(err).To(BeNil())
	KspDeleteAll()
})

var _ = AfterSuite(func() {
	err := K8sDelete([]string{"res/ubuntu-deployment.yaml"})
	Expect(err).To(BeNil())
	KspDeleteAll()
})

func getUbuntuPod(name string, ant string) string {
        pods, err := K8sGetPods(name, "nptest", []string{ant}, 60)
        Expect(err).To(BeNil())
        Expect(len(pods)).To(Equal(1))
        return pods[0]
}


var _ = Describe("Namespace", func() {
	var ubuntu string

	BeforeEach(func() {
		ubuntu = getUbuntuPod("ubuntu-1-deployment-","container.apparmor.security.beta.kubernetes.io/ubuntu-1-container: localhost/kubearmor-nptest-ubuntu-1-deployment-ubuntu-1-container")
	})

	AfterEach(func() {
		KarmorLogStop()
		KspDeleteAll()
		// Remove all Namespace annotation
		sout, err := Kubectl("annotate ns nptest kubearmor-network-posture-")
		Expect(err).To(BeNil())
		Expect(sout).To(MatchRegexp("namespace/nptest annotated"))

		sout, err = Kubectl("annotate ns nptest kubearmor-file-posture-")
                Expect(err).To(BeNil())
                Expect(sout).To(MatchRegexp("namespace/nptest annotated"))

		sout, err = Kubectl("annotate ns nptest kubearmor-capabilities-posture-")
                Expect(err).To(BeNil())
                Expect(sout).To(MatchRegexp("namespace/nptest annotated"))
	})

	Describe("Policy Apply", func() {

		It("check default posture for network", func() {
			// Apply policy
			err := K8sApply([]string{"res/network.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nptest", "Network", ubuntu)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "curl google.com"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("Could not resolve host: google.com"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 25)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("%+v\n", alerts[0])
			Expect(alerts[len(alerts)-1].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[len(alerts)-1].Action).To(Equal("Block"))
			Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/usr/bin/curl"))

			// delete policy
			err = K8sDelete([]string{"res/network.yaml"})
			Expect(err).To(BeNil())

		})

		It("check default posture for file/process", func() {
                        // Apply policy
                        err := K8sApply([]string{"res/process.yaml"})
                        Expect(err).To(BeNil())

                        // Start Kubearmor Logs
                        err = KarmorLogStart("policy", "nptest", "Process", ubuntu)
                        Expect(err).To(BeNil())

                        sout, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "ls"})
                        Expect(err).To(BeNil())
                        fmt.Printf("OUTPUT: %s\n", sout)
                        Expect(sout).To(MatchRegexp("Permission denied"))

                        // check policy violation alert
                        _, alerts, err := KarmorGetLogs(5*time.Second, 25)
                        Expect(err).To(BeNil())
                        Expect(len(alerts)).To(BeNumerically(">=", 1))
                        fmt.Printf("%+v\n", alerts[0])
                        Expect(alerts[len(alerts)-1].PolicyName).To(Equal("DefaultPosture"))
                        Expect(alerts[len(alerts)-1].Action).To(Equal("Block"))
                        Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/bin/ls"))

                        // delete policy
                        err = K8sDelete([]string{"res/process.yaml"})
                        Expect(err).To(BeNil())

                })

		It("check default posture with kubearmor-network-posture=audit", func() {
                        // Apply policy
                        err := K8sApply([]string{"res/network.yaml"})
                        Expect(err).To(BeNil())

			// Set Namespace annotation
			sout, err := Kubectl("annotate ns nptest kubearmor-network-posture=audit --overwrite")
			Expect(err).To(BeNil())
			Expect(sout).To(MatchRegexp("namespace/nptest annotated"))
			time.Sleep(10*time.Second)

                        // Start Kubearmor Logs
                        err = KarmorLogStart("policy", "nptest", "Network", ubuntu)
                        Expect(err).To(BeNil())

                        sout, _, err = K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "curl google.com"})
                        Expect(err).To(BeNil())
                        fmt.Printf("OUTPUT: %s\n", sout)
                        Expect(sout).To(MatchRegexp("301 Moved"))

                        // Check policy violation alert
                        _, alerts, err := KarmorGetLogs(5*time.Second, 25)
                        Expect(err).To(BeNil())
                        Expect(len(alerts)).To(BeNumerically(">=", 1))
                        fmt.Printf("%+v\n", alerts[0])
                        Expect(alerts[len(alerts)-1].PolicyName).To(Equal("DefaultPosture"))
                        Expect(alerts[len(alerts)-1].Action).To(Equal("Audit"))
                        Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/usr/bin/curl"))

			// Remove Namespace annotation
                        sout, err = Kubectl("annotate ns nptest kubearmor-network-posture-")
                        Expect(err).To(BeNil())
                        Expect(sout).To(MatchRegexp("namespace/nptest annotated"))

                        // Delete policy
                        err = K8sDelete([]string{"res/network.yaml"})
                        Expect(err).To(BeNil())

                })

		It("check default posture with kubearmor-file-posture=audit", func() {
                        // Apply policy
                        err := K8sApply([]string{"res/process.yaml"})
                        Expect(err).To(BeNil())

			// Set Namespace annotation
			sout, err := Kubectl("annotate ns nptest kubearmor-file-posture=audit --overwrite")
			Expect(err).To(BeNil())
			Expect(sout).To(MatchRegexp("namespace/nptest annotated"))
			time.Sleep(10*time.Second)

                        // Start Kubearmor Logs
                        err = KarmorLogStart("policy", "nptest", "Process", ubuntu)
                        Expect(err).To(BeNil())

                        sout, _, err = K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "ls"})
                        Expect(err).To(BeNil())
                        fmt.Printf("OUTPUT: %s\n", sout)
                        Expect(sout).To(MatchRegexp("bin"))

                        // Check policy violation alert
                        _, alerts, err := KarmorGetLogs(5*time.Second, 25)
                        Expect(err).To(BeNil())
                        Expect(len(alerts)).To(BeNumerically(">=", 1))
                        fmt.Printf("%+v\n", alerts[0])
                        Expect(alerts[len(alerts)-1].PolicyName).To(Equal("DefaultPosture"))
                        Expect(alerts[len(alerts)-1].Action).To(Equal("Audit"))
                        Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/bin/ls"))

			// Remove Namespace annotation
                        sout, err = Kubectl("annotate ns nptest kubearmor-file-posture-")
                        Expect(err).To(BeNil())
                        Expect(sout).To(MatchRegexp("namespace/nptest annotated"))

                        // Delete policy
                        err = K8sDelete([]string{"res/process.yaml"})
                        Expect(err).To(BeNil())

                })

		It("check default posture for network with block", func() {
			// Apply policy
			err := K8sApply([]string{"res/network2.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nptest", "Network", ubuntu)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "curl google.com"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("Could not resolve host: google.com"))

			// check policy violation alert
			_, alerts, err := KarmorGetLogs(5*time.Second, 25)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			fmt.Printf("%+v\n", alerts[0])
			Expect(alerts[len(alerts)-1].PolicyName).To(Equal("network-block-udp"))
			Expect(alerts[len(alerts)-1].Action).To(Equal("Block"))
			Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/usr/bin/curl"))

			// delete policy
			err = K8sDelete([]string{"res/network2.yaml"})
			Expect(err).To(BeNil())

		})

		It("check default posture for file/process with block", func() {
                        // Apply policy
                        err := K8sApply([]string{"res/process2.yaml"})
                        Expect(err).To(BeNil())

                        // Start Kubearmor Logs
                        err = KarmorLogStart("policy", "nptest", "Process", ubuntu)
                        Expect(err).To(BeNil())

                        sout, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "ls"})
                        Expect(err).To(BeNil())
                        fmt.Printf("OUTPUT: %s\n", sout)
                        Expect(sout).To(MatchRegexp("Permission denied"))

                        // check policy violation alert
                        _, alerts, err := KarmorGetLogs(5*time.Second, 25)
                        Expect(err).To(BeNil())
                        Expect(len(alerts)).To(BeNumerically(">=", 1))
                        fmt.Printf("%+v\n", alerts[0])
                        Expect(alerts[len(alerts)-1].PolicyName).To(Equal("process-block-ls"))
                        Expect(alerts[len(alerts)-1].Action).To(Equal("Block"))
                        Expect(alerts[len(alerts)-1].ProcessName).To(Equal("/bin/ls"))

                        // delete policy
                        err = K8sDelete([]string{"res/process2.yaml"})
                        Expect(err).To(BeNil())

                })

		It("check default posture for capabilities", func() {
			// Setup
			_, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "touch dummy"})
                        Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "useradd test"})
                        Expect(err).To(BeNil())

			// Apply policy
			err = K8sApply([]string{"res/capabilities.yaml"})
			Expect(err).To(BeNil())

			// Check execution
			sout, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "chown test dummy"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("Operation not permitted"))

			// Delete policy
			err = K8sDelete([]string{"res/capabilities.yaml"})
			Expect(err).To(BeNil())

		})

		It("check default posture for capabilities with kubearmor-capabilities-posture=audit", func() {
                        // Setup
                        _, _, err := K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "touch dummy"})
                        Expect(err).To(BeNil())
                        _, _, err = K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "useradd test"})
                        Expect(err).To(BeNil())

                        // Apply policy
                        err = K8sApply([]string{"res/capabilities.yaml"})
                        Expect(err).To(BeNil())

			// Set Namespace annotation
                        sout, err := Kubectl("annotate ns nptest kubearmor-capabilities-posture=audit --overwrite")
                        Expect(err).To(BeNil())
                        Expect(sout).To(MatchRegexp("namespace/nptest annotated"))
                        time.Sleep(10*time.Second)

                        // Check execution
                        sout, _, err = K8sExecInPod(ubuntu, "nptest",[]string{"bash", "-c", "chown test dummy"})
                        Expect(err).To(BeNil())
                        fmt.Printf("OUTPUT: %s\n", sout)
                        Expect(sout).To(Equal(""))

			// Remove Namespace annotation
                        sout, err = Kubectl("annotate ns nptest kubearmor-capabilities-posture-")
                        Expect(err).To(BeNil())
                        Expect(sout).To(MatchRegexp("namespace/nptest annotated"))

                        // Delete policy
                        err = K8sDelete([]string{"res/capabilities.yaml"})
                        Expect(err).To(BeNil())

                })

	})

})
