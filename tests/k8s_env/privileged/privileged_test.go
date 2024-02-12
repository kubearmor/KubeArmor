// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package privileged

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

	// configure privileged deployment
	err := K8sApplyFile("manifests/privileged-deploy.yaml")
	Expect(err).To(BeNil())

	err = K8sApplyFile("manifests/caps-all-deploy.yaml")
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())

})

var _ = AfterSuite(func() {
	// delete privileged deployment

	err := K8sDelete([]string{"manifests/caps-all-deploy.yaml"})
	Expect(err).To(BeNil())

	err = K8sDelete([]string{"manifests/privileged-deploy.yaml"})
	Expect(err).To(BeNil())

})

func getUbuntuPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "privileged", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Ksp", func() {
	var priv string
	var caps string
	BeforeEach(func() {
		priv = getUbuntuPod("privileged-deployment", "kubearmor-policy: enabled")
		caps = getUbuntuPod("caps-deployment", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
	})

	Describe("Privileged and ALL capabilities enabled containers test", func() {

		It("policies work for containers with all Capabilities enabled", func() {
			if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("Skipping due to apparmor specific policy")
			}
			err := K8sApply([]string{"manifests/caps-container-block-ls.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "privileged", "Process", caps)
			Expect(err).To(BeNil())

			// execute ls inside priv-container - would block
			sout, _, err := K8sExecInPodWithContainer(caps, "privileged", "caps-container",
				[]string{"bash", "-c", "ls /"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// alert should be present for the above block
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "caps-container",
				PolicyName:    "caps-container-block-ls",
				Action:        "Block",
				Result:        "Permission denied",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeTrue())
		})

		It("policies work for privileged containers in Containerd", func() {

			if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("Skipping due to apparmor specific policy")
			}

			if K8sRuntime() == "cri-o" || K8sRuntime() == "docker" {
				Skip("Only containerd is needed for this test")
			}

			err := K8sApply([]string{"manifests/priv-container-block-ls.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "privileged", "Process", priv)
			Expect(err).To(BeNil())

			// execute ls inside priv-container - would block
			sout, _, err := K8sExecInPodWithContainer(priv, "privileged", "priv-container",
				[]string{"bash", "-c", "ls /"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp(".*Permission denied"))

			// alert should be present for the above block
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "priv-container",
				PolicyName:    "privileged-container-block-ls",
				Action:        "Block",
				Result:        "Permission denied",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeTrue())
		})

		It("won't block mount by default for privileged/all capabilities enabled containers", func() {
			// execute mount inside priv-container - would pass

			err := KarmorLogStart("policy", "privileged", "Syscall", priv)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(priv, "privileged", "priv-container",
				[]string{"bash", "-c", "mkdir /mnt/test"})
			Expect(err).To(BeNil())
			sout, _, err = K8sExecInPodWithContainer(priv, "privileged", "priv-container",
				[]string{"bash", "-c", "mount /dev/loop0 /mnt/test"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			// TODO: match syscall alerts for mount once syscall audit events are fixed
			/*
				expect := protobuf.Alert{
					PolicyName: "DefaultPosture",
					Result:     "Passed",
					Data:       "syscall=SYS_MOUNT",
				}
			*/

			// no alert should be present for the above
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "priv-container",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeFalse())

		})

		It("won't block mount by default for all capabilities enabled containers", func() {

			err := KarmorLogStart("policy", "privileged", "Syscall", priv)
			Expect(err).To(BeNil())

			err = K8sApply([]string{"manifests/caps-container-block-ls.yaml"})
			Expect(err).To(BeNil())

			err = KarmorLogStart("policy", "privileged", "Syscall", caps)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(priv, "privileged", "caps-container",
				[]string{"bash", "-c", "mkdir /mnt/test"})
			Expect(err).To(BeNil())
			sout, _, err = K8sExecInPodWithContainer(priv, "privileged", "caps-container",
				[]string{"bash", "-c", "mount /dev/loop0 /mnt/test"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			// TODO: match syscall alerts for mount once syscall audit events are fixed
			/*
				expect := protobuf.Alert{
					PolicyName: "DefaultPosture",
					Result:     "Passed",
					Data:       "syscall=SYS_MOUNT",
				}
			*/

			// no alert should be present for the above
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "caps-container",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeFalse())
		})

		It("won't block umount by default for privileged containers", func() {
			// execute umount inside priv-container - would pass
			// Start KubeArmor Logs
			if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("Skipping due to apparmor specific policy")
			}

			err := KarmorLogStart("policy", "privileged", "Syscall", priv)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(priv, "privileged", "priv-container",
				[]string{"bash", "-c", "umount /var/run/secrets/kubernetes.io/serviceaccount"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			// no alert should be present for the above
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "priv-container",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeFalse())

			// execute umount inside unpriv-container - would fail
			sout, _, err = K8sExecInPodWithContainer(priv, "privileged", "unpriv-container",
				[]string{"bash", "-c", "umount /var/run/secrets/kubernetes.io/serviceaccount"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect = &protobuf.Alert{
				PolicyName: "DefaultPosture",
				Action:     "Block",
				Result:     "Operation not permitted",
				Data:       "syscall=SYS_UMOUNT2",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("won't block umount by default for all capabilities enabled containers", func() {
			// execute umount inside priv-container - would pass
			// Start KubeArmor Logs
			if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("Skipping due to apparmor specific policy")
			}

			err := KarmorLogStart("policy", "privileged", "Syscall", caps)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPodWithContainer(priv, "privileged", "caps-container",
				[]string{"bash", "-c", "umount /var/run/secrets/kubernetes.io/serviceaccount"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			// no alert should be present for the above
			expect := &protobuf.Alert{
				NamespaceName: "privileged",
				ContainerName: "caps-container",
			}

			logs, err := KarmorGetTargetAlert(5*time.Second, expect)
			Expect(err).To(BeNil())
			Expect(logs.Found).To(BeFalse())

		})

	})
})
