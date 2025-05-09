// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor
package networktests

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

	// configure multiubuntu deployment
	err := K8sApplyFile("res/multiubuntu-deployment.yaml")
	Expect(err).To(BeNil())

	// delete all KSPs
	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	// delete multiubuntu deployment
	err := K8sDelete([]string{"res/multiubuntu-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getUbuntuPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "multiubuntu", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

var _ = Describe("Network Tests", func() {
	Describe("Network tests ksp", func() {
		var ub1 string
		BeforeEach(func() {
			ub1 = getUbuntuPod("ubuntu-1", "kubearmor-policy: enabled")
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
				err := K8sApplyFile("res/ksp-ubuntu-1-audit-net-icmp.yaml")
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

				if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
					Skip("Skipping due to policy not supported by bpflsm enforcer")
				}

				// Apply Policy
				err := K8sApplyFile("res/ksp-ubuntu-1-block-net-raw-cap.yaml")
				Expect(err).To(BeNil())

				// Start KubeArmor Logs
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())

				// to wait for apparmor policy to be generated
				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "arping -c 1 127.0.0.1"},
					MatchRegexp("CAP_NET_RAW.*required"), true,
				)

				expect := protobuf.Alert{
					PolicyName: "ksp-ubuntu-1-block-net-raw-cap",
					Severity:   "1",
					Action:     "Block",
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
				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "curl 40.114.177.156"},
					MatchRegexp("<html>((?:.*\r?\n?)*)</html>"), true,
				)

				expect := protobuf.Log{
					Result: "Passed",
					Source: "/usr/bin/curl 40.114.177.156",
				}

				res, err := KarmorGetTargetLogs(5*time.Second, &expect)
				Expect(err).To(BeNil())
				Expect(res.Found).To(BeTrue())

				// Test 2: when policy applied only tcp traffic is allowed from source

				// Apply Policy
				err = K8sApplyFile("res/ksp-ubuntu-1-allow-net-tcp-from-source.yaml")
				Expect(err).To(BeNil())
				time.Sleep(5 * time.Second)
				// Start KubeArmor Logs
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())

				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "curl duckduckgo.com"},
					MatchRegexp("Could not resolve host: duckduckgo.com"), true,
				)

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
				err := K8sApplyFile("res/ksp-ubuntu-1-audit-net-raw.yaml")
				Expect(err).To(BeNil())

				// Start KubeArmor Logs
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())

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
				err := K8sApplyFile("res/ksp-ubuntu-1-block-net-raw.yaml")
				Expect(err).To(BeNil())

				// Start KubeArmor Logs
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())
				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "arping -c 1 127.0.0.1"},
					MatchRegexp("arping.*Permission denied"), true,
				)

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

			It("it can block all network traffic", func() {
				// Apply Policy
				err := K8sApplyFile("res/ksp-ubuntu-1-block-net-all.yaml")
				Expect(err).To(BeNil())

				// Start KubeArmor Logs
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())
				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "ping -c 1 127.0.0.1"},
					MatchRegexp("ping.*Permission denied"), true,
				)

				expect := protobuf.Alert{
					PolicyName: "ksp-ubuntu-1-block-net-all",
					Severity:   "8",
					Action:     "Block",
					Result:     "Permission denied",
				}

				res, err := KarmorGetTargetAlert(5*time.Second, &expect)
				Expect(err).To(BeNil())
				Expect(res.Found).To(BeTrue())

			})

		})

	})
	var _ = Describe("Network block posture tests", func() {
		var ub1 string
		BeforeEach(func() {
			//annotate block posture on namespace level
			_, err := Kubectl("annotate ns multiubuntu kubearmor-network-posture=block --overwrite")
			Expect(err).To(BeNil())
			ub1 = getUbuntuPod("ubuntu-1", "kubearmor-policy: enabled")
			time.Sleep(5 * time.Second)
		})

		AfterEach(func() {
			KarmorLogStop()
			err := DeleteAllKsp()
			Expect(err).To(BeNil())
		})

		Describe("Apply network policy", func() {
			It("can whitelist use of certain network protocols used by a package, such as tcp", func() {
				// Apply policy
				err := K8sApplyFile("res/ksp-ubuntu-1-allow-net-tcp-from-source.yaml")
				Expect(err).To(BeNil())
				time.Sleep(5 * time.Second)
				// Start Kubearmor Logs
				err = KarmorLogStart("system", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())
				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "curl 40.114.177.156"},
					MatchRegexp("<html>((?:.*\r?\n?)*)</html>"), true,
				)

				// test block posture
				err = KarmorLogStart("policy", "multiubuntu", "Network", ub1)
				Expect(err).To(BeNil())

				AssertCommand(ub1, "multiubuntu", []string{"bash", "-c", "curl duckduckgo.com"},
					MatchRegexp("Could not resolve host: duckduckgo.com"), true,
				)

				expectAlert := protobuf.Alert{
					PolicyName: "DefaultPosture",
					Severity:   "",
					Action:     "Block",
					Result:     "Permission denied",
				}

				res, err := KarmorGetTargetAlert(5*time.Second, &expectAlert)
				Expect(err).To(BeNil())
				Expect(res.Found).To(BeTrue())

			})

		})
	})

})
