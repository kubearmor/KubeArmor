// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package ksp

import (
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {

	// configure multiubuntu deployment
	err := K8sApplyFile("multiubuntu/multiubuntu-deployment.yaml")
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())

	// enable kubearmor port forwarding
	err = KubearmorPortForward()
	Expect(err).To(BeNil())

})

var _ = AfterSuite(func() {
	KubearmorPortForwardStop()
})

func getUbuntuPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "multiubuntu", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Ksp", func() {
	var ub1, ub3, ub4 string
	BeforeEach(func() {
		ub1 = getUbuntuPod("ubuntu-1",
			"container.apparmor.security.beta.kubernetes.io/ubuntu-1-container: localhost/kubearmor-multiubuntu-ubuntu-1-deployment-ubuntu-1-container")
		ub3 = getUbuntuPod("ubuntu-3",
			"container.apparmor.security.beta.kubernetes.io/ubuntu-3-container: localhost/kubearmor-multiubuntu-ubuntu-3-deployment-ubuntu-3-container")
		ub4 = getUbuntuPod("ubuntu-4",
			"container.apparmor.security.beta.kubernetes.io/ubuntu-4-container: localhost/kubearmor-multiubuntu-ubuntu-4-deployment-ubuntu-4-container")
		fmt.Print(ub1, ub4, ub3)
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
	})

	Describe("Apply Network Policies", func() {

		It("it can audit all network trafic on icmp protocol", func() {
			// multiubuntu_test_07, github_test_09

			// Apply policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-audit-net-icmp.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "ping -c 1 127.0.0.1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("PING.*127.0.0.1"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-audit-net-icmp",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
			}

			// check policy alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block all network traffic on net-raw protocol", func() {
			// multiubuntu_test_03, github_test_10

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-net-raw-cap.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "arping -c 1 127.0.0.1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("CAP_NET_RAW.*required"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-net-raw-cap",
				Severity:   "1",
				Action:     "Block",
				Result:     "Operation not permitted",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can allow all network traffic on tcp protocol from source path", func() {
			// github_test_12

			// Test 1 : Initially there's no allow policy so network traffic on any protocol
			// Should passed

			err := KarmorLogStart("system", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "curl 142.250.193.46"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("<A HREF=\"http://www.google.com/\">here</A>"))

			expect := protobuf.Log{
				Result: "Passed",
				Source: "/usr/bin/curl 142.250.193.46",
			}

			res, err := KarmorGetTargetLogs(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: when policy applied only tcp traffic is allowed from source

			// Apply Policy
			err = K8sApplyFile("multiubuntu/ksp-ubuntu-1-allow-net-tcp-from-source.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "curl google.com"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("Could not resolve host: google.com"))

			expectAlert := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expectAlert)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can audit all network traffic on net-raw protocol", func() {
			// github_test_13

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-audit-net-raw.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // for policy

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "arping -c 1 127.0.0.1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("ARPING 127.0.0.1"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-audit-net-raw",
				Severity:   "8",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can block all network traffic on net-raw protocol", func() {
			//  multiubuntu_test_28, github_test_14

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-net-raw.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "arping -c 1 127.0.0.1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-net-raw",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

	})

	Describe("Apply Process Policies", func() {
		It("it can block a process from path for all pods in a group", func() {
			// multiubuntu_test_01

			// Test 1: testing ubuntu-1 pod in group-1

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-1-block-proc-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs in ubuntu-1 pod
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "sleep 1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("sleep.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-1-block-proc-path",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: testing ubuntu-3 pod in group-1

			// Start KubeArmor Logs in ubuntu-3 pod
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub3)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "sleep 1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("sleep.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-group-1-block-proc-path",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can audit a process from path for all pods in a group", func() {
			// multiubuntu_test_02

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-audit-proc-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub4)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // wait for policy

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "sleep 1"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "ksp-group-2-audit-proc-path",
				Severity:   "4",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})
		It("it can block all the processes, direct child of a directory", func() {
			// multiubuntu_test_04

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-proc-dir.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "route"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("route.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-proc-dir",
				Severity:   "6",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block all the processes in a directory recursively", func() {
			// multiubuntu_test_05

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-proc-dir-recursive.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "whoami"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("whoami.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-proc-dir-recursive",
				Severity:   "2",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can block a process execution from source path for all the pods in a group", func() {
			// multiubuntu_test_12, github_test_01

			// Test 1: trying to access blocked process from source

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-1-block-proc-path-from-source.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "/bin/dash -c ls"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("dash.*ls.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-1-block-proc-path-from-source",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: any other process should be allowed to access from source

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "Process", ub1)
			Expect(err).To(BeNil())

			// /bin/bash -c pwd shoud passed as only /bin/ls is blocked by policy
			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "/bin/dash -c pwd"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			// Expect(sout).To(Equal("/\r\n"))

			expectLog := protobuf.Log{
				Resource: "/bin/dash",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can allow the accesses to the process and files from a particular directory only", func() {
			// multiubuntu_test_08

			// Test 1: access to the non-permitted file should be denied

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-allow-proc-dir.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "cat /etc/hostname"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("hostname.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "hostname",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: accesss to the permitted files and processes should be allowed

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("password file"))

		})

		It("it can allow the accesses to a process path by the owner only", func() {
			// multiubuntu_test_14
			// Test 1: access to the process by the user other than owner should be denied(default)

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-allow-proc-path-owner.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "/home/user1/hello"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("hello.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: owner can execute the binary

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c '/home/user1/hello'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("helloworld"))
		})

		It("it can block all the accesses to a process path except access by the owner", func() {
			// multiubuntu_test_15

			// Test 1: access to the process by the user other than owner should be denied

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-block-proc-path-owner.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "Process", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "/home/user1/hello"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("hello.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-proc-path-owner",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: owner can execute the binary

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "Process", ub3)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c '/home/user1/hello'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("helloworld"))

			expectLog := protobuf.Log{
				Resource: "/home/user1/hello",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

	})

	Describe("Apply Files Policies", func() {

		It("it can allow accessing a file from source path", func() {
			// multiubuntu_test_17, github_test_05

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-allow-file-path-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /etc/hostname"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("hostname.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "hostname",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: from source allowed file path can be accessed

			// cat /secret.txt should result in passed as per the applied policy
			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /secret.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file"))

		})

		It("it can block accessing a file directory recursively", func() {
			// multiubuntu_test_06

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-block-file-dir-recursive.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // for policy

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("password.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-dir-recursive",
				Severity:   "9",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can audit accessing a file from source path", func() {

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-audit-file-path-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // for policy

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /secret.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-2-audit-file-path-from-source-path",
				Severity:   "5",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can audit accessing a file directory recursively", func() {
			// github_test_02

			// test 1: check for file access

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-audit-file-dir.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // for policy

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("password file"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-audit-file-dir",
				Severity:   "5",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// test 2: check for subdirectory file access

			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/keys/priv.key"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("key file"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-audit-file-dir",
				Severity:   "5",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can block accessing a file from source path", func() {
			// multiubuntu_test_18, github_test_04

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-block-file-path-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /secret.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-2-block-file-path-from-source-path",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can allow accessing a file owner only from source path", func() {
			// Test 1: access by user other than owner should be denied

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-allow-file-path-owner-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "secret_data1.txt",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: owner is allowed to access the file

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

		})

		It("it can audit accessing a file owner only from source path", func() {

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-audit-file-path-owner-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second) // for policy

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-2-audit-file-path-owner-from-source-path",
				Severity:   "7",
				Action:     "Audit",
				Result:     "Passed",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block accessing a file owner only from source path", func() {
			// Test 1: user other than owner should not be allowed to access the file from source path

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-group-2-block-file-path-owner-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-group-2-block-file-path-owner-from-source-path",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: owner is allowed to access the file from source path

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			expectLog := protobuf.Log{
				Resource: "secret_data1.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block accessing a file using file pattern except readonly access from owner", func() {
			// multiubuntu_test_27, github_test_08

			// Test 1: access by any other user than the owner should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-file-pattern-owner-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-pattern-owner-readonly",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: readonly access by the owner shoudl be allowed

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			expectLog := protobuf.Log{
				Resource: "secret_data1.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: write operation by a non-owner user should be blocked

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			// as the file is read-only this should result in permission denied
			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "echo root >> /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-pattern-owner-readonly",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 4: write operation by the owner should also be blocked

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			// as the file is read-only this should result in permission denied
			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'echo test >> /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-pattern-owner-readonly",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block all the access to a directory recursively except readonly by the owner", func() {
			// multiubuntu_test_25, github_test_07

			// Test 1: non-owner user access should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-block-file-dir-recursive-owner-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/dir1/key1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("key1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-recursive-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: readonly access by the owner is allowed

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			// Test 3: readonly access to a file in a subdirectory by the owner is allowed

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/dir1/key1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("key file 1"))

			// Test 4: write operation by the non-owner shoudl also be blocked
			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "echo root >> /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-recursive-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 5: owner also not allowed write operation on the file

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'echo user1 >> /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-recursive-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 6: owner also not allowed write operation on the file in subdirectory too

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'echo user1 >> /home/user1/dir1/key1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("key1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-recursive-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block all the access to a directory except readonly by the owner", func() {
			// multiubuntu_test_26

			// Test 1: non-owner user access should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-block-file-dir-owner-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: readonly access by the owner is allowed
			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			expectLog := protobuf.Log{
				Resource: "secret_data1.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: write operation by the non-owner shoudl also be blocked
			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "echo root >> /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 4: owner also not allowed write operation on the file

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'echo user1 >> /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-3-block-file-dir-owner-readonly",
				Severity:   "7",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it will allow a file path accessible read-only to owner from source path", func() {
			// Test 1: file access from source by non-owner user should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-allow-file-path-owner-readonly-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -r /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: write operation from source path by non-owner user should be blocked

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -w /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect = protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: readonly access to the file from source by the owner is allowed

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c './readwrite -r /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			// Expect(sout).To(ContainSubstring("s"))

			expectLog := protobuf.Log{
				Source: "/home/user1/secret_data1.txt",
				Result: "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it will block a file path access except read-only accessible to owner from source path", func() {
			// multiubuntu_test_23

			// Test 1: write operation on the file by the owner should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-block-file-path-owner-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c '/readwrite -w /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("Error"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: write operation on the file by non-owner user should be blocked

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -w /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("Error"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: readonly access by the non-owner should not be allowed

			// Start KubeArmor Logs
			// err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			// Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: readonly access by the owner should be allowed

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			expectLog := protobuf.Log{
				Resource: "secret_data1.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it will block a file path access except read-only accessible to owner from source path", func() {
			// multiubuntu_test_24

			// Test 1: write operation on the file from source by the owner should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-block-file-path-owner-readonly-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c '/readwrite -w /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly-from-source-path",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: write operation on the file from source path by non-owner user should be blocked

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -w /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly-from-source-path",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: write operation on the file from source by the owner should also be blocked

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c '/readwrite -w /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-owner-readonly-from-source-path",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 4: readonly access from source by the owner should be allowed

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			// Expect(sout).To(ContainSubstring("secret file user1"))

			expectLog := protobuf.Log{
				Resource: "secret_data1.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can allow readonly access to file path by owner only", func() {
			// multiubuntu_test_22, github_test_06

			// Test 1: access by the non-owner user should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-allow-file-path-owner-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "secret_data1.txt",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: readonly access by the owner shoudl be allowed

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			// Test 3: access to some other file by the owner shoudl be blocked by default

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/otherfile.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("otherfile\\.txt.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "otherfile.txt",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can allow access to a file by the owner only", func() {
			// multiubuntu_test_21

			// Test 1: access by other user than owner should be blocked

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-3-allow-file-path-owner.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub3)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "cat /home/user1/secret_data1.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("secret_data1\\.txt.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "secret_data1",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: access by the owner should be allowed

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'cat /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("secret file user1"))

			// Test 3: write operation on the file by the owner should also be allowed

			sout, _, err = K8sExecInPod(ub3, "multiubuntu",
				[]string{"bash", "-c", "su - user1 -c 'echo user1 >> /home/user1/secret_data1.txt'"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

		})

		It("it can block access to file path from source path except readonly access is allowed", func() {
			// multiubuntu_test_20

			// Test 1: readonly access from the source should be allowed

			// Apply Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-block-file-path-readonly-from-source-path.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -r /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("p"))

			expectLog := protobuf.Log{
				Resource: "/credentials/password",
				Result:   "Passed",
			}

			res, err := KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: write operation from the source should be blocked

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -w /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-readonly-from-source-path",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: access to some other file from source should not be blocked

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -r /secret.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("s"))

			expectLog = protobuf.Log{
				Resource: "secret.txt",
				Result:   "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can allow readonly access to a file path from given source path", func() {
			// multiubuntu_test_19

			// Test 1: reading the file from source path should be passed

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-allow-file-path-readonly-from-source-path.yaml")
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -r /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("p"))

			// Test 2: wrinting to the file even from source path shoould be denied

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -w /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "password",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3: reading some other file should be denied as not allowed by the policy

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "./readwrite -r /secret.txt"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)

			expect = protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "secret.txt",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can block access to a file path except readonly access is allowed", func() {
			// multiubuntu_test_16

			// Test 1: trying to write the file with readonly permissions

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-block-file-path-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "echo test >> /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("password.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-4-block-file-path-readonly",
				Severity:   "10",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2: reading the file should result in success

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("password file"))

			expectLog := protobuf.Log{
				Source: "/credentials/password",
				Result: "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

		})

		It("it can block access to the files that following a given pattern", func() {
			// multiubuntu_test_11, github_test_03

			// Test 1 : trying to access file following the pattern

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-file-pattern.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /etc/shadow"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("shadow.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-pattern",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 : trying to access another file following the pattern

			sout, _, err = K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /etc/gshadow"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("gshadow.*Permission denied"))

			expect = protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-pattern",
				Severity:   "5",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block access to a file directory recursively", func() {
			// multiubuntu_test_13

			// test 1

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-1-block-file-dir-recursive.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /run/secrets/kubernetes.io/serviceaccount/token"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("token.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "ksp-ubuntu-1-block-file-dir-recursive",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can block access to a file directory recursively using native apparmor spec", func() {
			// multiubuntu_test_10, github_test_11

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/nsp-group-1-block-file-dir-recursive.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub1)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub1, "multiubuntu",
				[]string{"bash", "-c", "cat /etc/hostname"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("hostname.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "hostname",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("it can allow readonly access to a file path", func() {
			// multiubuntu_test_09

			// Test: write to the file with readonly permissions

			// Apply KubeArmor Policy
			err := K8sApplyFile("multiubuntu/ksp-ubuntu-4-allow-file-path-readonly.yaml")
			Expect(err).To(BeNil())

			// Start KubeArmor Logs
			err = KarmorLogStart("policy", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err := K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "echo test >> /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(MatchRegexp("password.*Permission denied"))

			expect := protobuf.Alert{
				PolicyName: "DefaultPosture",
				Severity:   "",
				Action:     "Block",
				Result:     "Permission denied",
				Resource:   "password",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 : reading file should result in success

			// Start KubeArmor Logs
			err = KarmorLogStart("system", "multiubuntu", "File", ub4)
			Expect(err).To(BeNil())

			sout, _, err = K8sExecInPod(ub4, "multiubuntu",
				[]string{"bash", "-c", "cat /credentials/password"})
			Expect(err).To(BeNil())
			fmt.Printf("OUTPUT: %s\n", sout)
			Expect(sout).To(ContainSubstring("password file"))

			expectLog := protobuf.Log{
				Source: "/credentials/password",
				Result: "Passed",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

	})
})
