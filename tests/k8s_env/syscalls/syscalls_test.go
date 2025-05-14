// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package syscalls

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install wordpress-mysql app in syscalls ns
	err := K8sApply([]string{"manifests/ubuntu-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all KSPs
	KspDeleteAll()
})

var _ = AfterSuite(func() {
	// delete wordpress-mysql app from syscalls ns
	err := K8sDelete([]string{"manifests/ubuntu-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getUbuntuPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "syscalls", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Syscalls", func() {
	var ubuntu string
	_ = ubuntu

	BeforeEach(func() {
		ubuntu = getUbuntuPod("ubuntu-1-deployment-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		KspDeleteAll()
	})

	Describe("Match syscalls", func() {
		It("can detect unlink syscall", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/unlink.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-all-unlink",
				Severity:   "3",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall from dir source", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/unlink-fromsource.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "cp /usr/bin/unlink /bin/unlink"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "/bin/unlink /dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-fromsource",
				Severity:   "4",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall from recursive dir source", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/unlink-fromsource-dir-recursive.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "mkdir -p /foo/bar"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "cp /usr/bin/unlink /foo/bar/unlink"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "/foo/bar/unlink /dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-fromsource-dir-recursive",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall from path source", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/unlink-fromsource-path.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "cp /usr/bin/unlink /unlink"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "/unlink /dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-fromsource-path",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

	})

	Describe("Match paths", func() {
		It("can detect unlink syscall recursive target", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/unlink.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall targets absolute file path", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/unlink-file-path.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-file-path",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target from absolute path", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/unlink-dir-recursive-fromsource-path.yaml"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "cp /usr/bin/unlink /bin/unlink"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "/bin/unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-dir-recursive-fromsource-path",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target from recursive dir", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/unlink-dir-recursive-fromsource-recursive-dir.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-dir-recursive-fromsource-recursive-dir",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target from dir", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/unlink-dir-recursive-fromsource-dir.yaml"})
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "cp /usr/bin/unlink /bin/unlink"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "/bin/unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-dir-recursive-fromsource-dir",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

	})

	Describe("Policy informations for matchsyscalls", func() {
		It("can detect unlink syscall recursive target with global informations", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/matchsyscalls-global-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-global-information",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Global message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with local informations", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/matchsyscalls-local-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-local-information",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with local informations when global is set", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/matchsyscalls-local-trumps-global-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-local-trumps-global-information",
				Severity:   "7",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with missing local informations when global is set", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchsyscalls/matchsyscalls-global-fill-missing-local-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-global-fill-missing-local-information",
				Severity:   "7",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})
	})

	Describe("Policy informations for matchpaths", func() {
		It("can detect unlink syscall recursive target with global informations", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/matchpaths-global-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-global-information",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Global message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with local informations", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/matchpaths-local-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-local-information",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with local informations when global is set", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/matchpaths-local-trumps-global-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-local-trumps-global-information",
				Severity:   "7",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("can detect unlink syscall recursive target with missing local informations when global is set", func() {
			// Apply policy
			err := K8sApply([]string{"manifests/matchpaths/matchpaths-global-fill-missing-local-information.yaml"})
			Expect(err).To(BeNil())

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "touch /home/dummy"})
			Expect(err).To(BeNil())
			_, _, err = K8sExecInPod(ubuntu, "syscalls", []string{"bash", "-c", "unlink /home/dummy"})
			Expect(err).To(BeNil())

			// check policy alert
			expect := protobuf.Alert{
				PolicyName: "audit-unlink-global-fill-missing-local-information",
				Severity:   "7",
				Action:     "Audit",
				Result:     "Passed",
				Message:    "Local message",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("mount will be blocked by default for a pod", func() {
			Skip("Skipping due to alerts only being generated when something is blocked by kubearmor")

			// Start KubeArmor Logs
			err := KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			// execute mount inside the pod
			sout, _, err := K8sExecInPod(ubuntu, "syscalls",
				[]string{"bash", "-c", "mkdir /mnt/test"})
			Expect(err).To(BeNil())
			sout, _, err = K8sExecInPod(ubuntu, "syscalls",
				[]string{"bash", "-c", "mount /home /mnt/test"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Action:     "Block",
				Result:     "Permission denied",
				Data:       "syscall=SYS_MOUNT",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("umount will be blocked by default for a pod as the capability not added", func() {

			Skip("Skipping due to alerts only being generated when something is blocked by kubearmor")

			// Start KubeArmor Logs
			err := KarmorLogStart("policy", "syscalls", "Syscall", ubuntu)
			Expect(err).To(BeNil())

			// execute umount inside the pod
			sout, _, err := K8sExecInPod(ubuntu, "syscalls",
				[]string{"bash", "-c", "umount /mnt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Action:     "Block",
				Result:     "Operation not permitted",
				Data:       "syscall=SYS_UMOUNT2",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})

})
