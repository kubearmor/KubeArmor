// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package csp

import (
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// install nginx deployment in nginx1 ns
	err := K8sApply([]string{"res/nginx-nginx1-deployment.yaml"})
	Expect(err).To(BeNil())

	// install nginx deployment in nginx2 ns
	err = K8sApply([]string{"res/nginx-nginx2-deployment.yaml"})
	Expect(err).To(BeNil())

	// delete all CSPs
	err = DeleteAllCsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// Delete debian deployment in nginx1 ns
	err := K8sDelete([]string{"res/debian-nginx1-deployment.yaml"})
	Expect(err).To(BeNil())

	// Delete nginx deployment in nginx1 ns
	err = K8sDelete([]string{"res/nginx-nginx1-deployment.yaml"})
	Expect(err).To(BeNil())

	// Delete nginx deployment in nginx2 ns
	err = K8sDelete([]string{"res/nginx-nginx2-deployment.yaml"})
	Expect(err).To(BeNil())

	// Delete nginx-later-deploy deployment in nginx1 ns
	err = K8sDelete([]string{"res/nginx-later-nginx1-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getNginxPod(name, namespace, ant string) string {
	pods, err := K8sGetPods(name, namespace, []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("csp", func() {
	var n1 string
	var n2 string

	BeforeEach(func() {
		n1 = getNginxPod("nginx1-", "nginx1", "kubearmor-policy: enabled")
		n2 = getNginxPod("nginx2-", "nginx2", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllCsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can block execution of pkg mgmt tools apt, In operator", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-in-operator-block-process.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_1

			// Test 1 - should block apt for ns nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx1", "Process", n1)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-in-operator-block-process",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block apt for ns nginx2
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx2", "Process", n2)
			Expect(err).To(BeNil())

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), true,
			)

			expectedLog := protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3 - should block apt for ns nginx1 (deployment is added after applying the cluster policy)

			// install nginx-later deployment in nginx1 ns
			err = K8sApply([]string{"res/nginx-later-nginx1-deployment.yaml"})
			Expect(err).To(BeNil())

			nl := getNginxPod("nginx-later-deploy", "nginx-later", "kubearmor-policy: enabled")

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx-later", "Process", nl)
			Expect(err).To(BeNil())

			AssertCommand(nl, "nginx-later", []string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			expect = protobuf.Alert{
				PolicyName: "csp-in-operator-block-process",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of access to file, In operator", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-in-operator-block-file-access.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_2

			// Test 1 - should block file access for ns nginx2
			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx2", "File", n2)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "cat /etc/host.conf"},
				MatchRegexp("host.conf.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-in-operator-block-file-access",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block file access for ns nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx1", "File", n1)
			Expect(err).To(BeNil())

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "cat /etc/host.conf"},
				ContainSubstring("multi on"), true,
			)

			expectedLog := protobuf.Log{
				Result: "Passed",
				Source: "/usr/bin/cat /etc/host.conf",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of pkg mgmt tools apt, NotIn operator", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-not-in-operator-block-process.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_3

			// Test 1 - should block apt in other then nginx1 ns
			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx2", "Process", n2)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-not-in-operator-block-process",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block apt for ns nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx1", "Process", n1)
			Expect(err).To(BeNil())

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), false,
			)

			expectedLog := protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of access to file, NotIn operator", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-not-in-operator-block-file-access.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_4

			// Test 1 - should block file access for ns nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx1", "File", n1)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "cat /etc/host.conf"},
				MatchRegexp("host.conf.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-not-in-operator-block-file-access",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block file access for ns nginx2
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx2", "File", n2)
			Expect(err).To(BeNil())

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "cat /etc/host.conf"},
				ContainSubstring("multi on"), false,
			)

			expectedLog := protobuf.Log{
				Result: "Passed",
				Source: "/usr/bin/cat /etc/host.conf",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of specific workload based on labels, In expression", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-matchlabels-in-block-process.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_5

			// Test 1 - should block apt for nginx workloads only in namespace nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx1", "Process", n1)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-matchlabels-in-block-process",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block apt for ns nginx2
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx2", "Process", n2)
			Expect(err).To(BeNil())

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), true,
			)

			expectedLog := protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3 - should not block apt for debian in ns nginx1

			// install debian deployment in nginx1 ns
			err = K8sApply([]string{"res/debian-nginx1-deployment.yaml"})
			Expect(err).To(BeNil())

			deb := getNginxPod("debian-app", "nginx1", "kubearmor-policy: enabled")

			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx1", "Process", deb)
			Expect(err).To(BeNil())

			AssertCommand(deb, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), true,
			)

			expectedLog = protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

		It("can block execution of specific workload based on labels, NotIn expression", func() {
			// Apply policy
			err := K8sApplyFile("res/csp-matchlabels-not-in-block-process.yaml")
			Expect(err).To(BeNil())

			// cluster_policy_test_5

			// Test 1 - should not block apt for nginx workloads only in namespace nginx1
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx1", "Process", n1)
			Expect(err).To(BeNil())

			// wait for policy creation
			time.Sleep(5 * time.Second)

			AssertCommand(n1, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), true,
			)

			expectedLog := protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err := KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 2 - should not block apt for ns nginx2
			// Start Kubearmor Logs
			err = KarmorLogStart("system", "nginx2", "Process", n2)
			Expect(err).To(BeNil())

			AssertCommand(n2, "nginx2", []string{"bash", "-c", "apt"},
				MatchRegexp(".*"), true,
			)

			expectedLog = protobuf.Log{
				Result:   "Passed",
				Resource: "/usr/bin/apt",
			}

			res, err = KarmorGetTargetLogs(5*time.Second, &expectedLog)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())

			// Test 3 - should block apt for debian in ns nginx1

			// install debian deployment in nginx1 ns
			err = K8sApply([]string{"res/debian-nginx1-deployment.yaml"})
			Expect(err).To(BeNil())

			deb := getNginxPod("debian-app", "nginx1", "kubearmor-policy: enabled")

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "nginx1", "Process", deb)
			Expect(err).To(BeNil())

			AssertCommand(deb, "nginx1", []string{"bash", "-c", "apt"},
				MatchRegexp("apt.*Permission denied"), true,
			)

			expect := protobuf.Alert{
				PolicyName: "csp-matchlabels-not-in-block-process",
				Severity:   "8",
				Action:     "Block",
				Result:     "Permission denied",
			}

			res, err = KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})

	})

})
