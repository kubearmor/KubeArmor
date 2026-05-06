// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package blockposture

import (
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	err := K8sApply([]string{"res/nginx-posture-deployment.yaml"})
	Expect(err).To(BeNil())

	_, err = Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
	Expect(err).To(BeNil())

	_, err = Kubectl("annotate ns nginx-posture kubearmor-file-posture=block --overwrite")
	Expect(err).To(BeNil())

	// Restart the deployment so the mutating webhook reliably injects the annotation,
	// overcoming any race condition during the initial namespace/deployment creation.
	_, err = Kubectl("rollout restart deployment nginx-posture-deployment -n nginx-posture")
	Expect(err).To(BeNil())

	time.Sleep(60 * time.Second)

	err = DeleteAllKsp()
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	err := K8sDelete([]string{"res/nginx-posture-deployment.yaml"})
	Expect(err).To(BeNil())
})

func getNginxPod(name string, ant string) string {
	pods, err := K8sGetPods(name, "nginx-posture", []string{ant}, 60)
	Expect(err).To(BeNil())
	Expect(len(pods)).To(Equal(1))
	return pods[0]
}

func probeNetworkBinary(pod, ns string) (bin string, args []string) {
	candidates := []struct {
		binary string
		args   []string
	}{
		{
			"curl",
			[]string{"sh", "-c", "curl -s --connect-timeout 5 -m 5 1.1.1.1"},
		},
		{
			"wget",
			[]string{"sh", "-c", "wget -q -T 5 -t 1 -O /dev/null http://1.1.1.1"},
		},
		{
			"nc",
			[]string{"sh", "-c", "nc -z -w 5 1.1.1.1 80"},
		},
	}

	for _, c := range candidates {
		out, _, err := K8sExecInPodWithContainer(pod, ns, "", []string{"sh", "-c", "which " + c.binary})
		if err == nil && len(strings.TrimSpace(out)) > 0 {
			return c.binary, c.args
		}
	}
	return "", nil
}

var _ = Describe("Posture", func() {

	var ng string

	BeforeEach(func() {
		ng = getNginxPod("nginx-posture-", "kubearmor-policy: enabled")
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllKsp()
		Expect(err).To(BeNil())
		time.Sleep(5 * time.Second)
	})

	Describe("Policy Apply", func() {
		It("can whitelist certain files accessed by a package while blocking all other sensitive content", func() {
			err := util.AnnotateNS("nginx-posture", "kubearmor-file-posture", "block")
			Expect(err).To(BeNil())

			err = K8sApplyFile("res/ksp-nginx-allow-file.yaml")
			Expect(err).To(BeNil())

			time.Sleep(10 * time.Second)

			err = KarmorLogStart("policy", "nginx-posture", "File", ng)
			Expect(err).To(BeNil())

			AssertCommand(
				ng, "nginx-posture", []string{"sh", "-c", "cat docker-entrypoint.sh"},
				MatchRegexp("cat.*Permission denied"), true,
			)

			AssertCommand(
				ng, "nginx-posture", []string{"sh", "-c", "cat /usr/share/nginx/html/index.html"},
				MatchRegexp("<!DOCTYPE html>((?:.*\r?\n?)*)</html>"), true,
			)

			_, alerts, err := KarmorGetLogs(10*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1))
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Action).To(Equal("Block"))
		})
	})

	Describe("Network Posture", func() {

		It("should block egress traffic and emit a DefaultPosture Network alert when file Allow policy is active", func() {
			_, err := Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
			Expect(err).To(BeNil())

			err = K8sApplyFile("res/ksp-nginx-allow-file.yaml")
			Expect(err).To(BeNil())
			time.Sleep(10 * time.Second)

			netBin, netArgs := probeNetworkBinary(ng, "nginx-posture")
			if netBin == "" {
				Skip("No network binary (curl/wget/nc) found in pod " + ng)
			}

			err = KarmorLogStart("policy", "nginx-posture", "Network", ng)
			Expect(err).To(BeNil())

			AssertCommand(
				ng, "nginx-posture", netArgs,
				MatchRegexp(`(?i)(permission denied|failed to connect|connection timed out|network unreachable|operation not permitted|exit status [1-9])`),
				true,
			)

			_, alerts, err := KarmorGetLogs(15*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(BeNumerically(">=", 1), "CRITICAL: No Network alert received. Binary used: %s", netBin)
			Expect(alerts[0].PolicyName).To(Equal("DefaultPosture"))
			Expect(alerts[0].Action).To(Equal("Block"))
			Expect(alerts[0].Operation).To(Equal("Network"))
		})

		It("should NOT emit a Network alert when performing an allowed file operation", func() {
			_, err := Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
			Expect(err).To(BeNil())

			err = K8sApplyFile("res/ksp-nginx-allow-file.yaml")
			Expect(err).To(BeNil())
			time.Sleep(10 * time.Second)

			err = KarmorLogStart("policy", "nginx-posture", "Network", ng)
			Expect(err).To(BeNil())

			AssertCommand(
				ng, "nginx-posture",
				[]string{"sh", "-c", "cat /usr/share/nginx/html/index.html"},
				MatchRegexp("<!DOCTYPE html>((?:.*\r?\n?)*)</html>"),
				false,
			)

			_, alerts, err := KarmorGetLogs(3*time.Second, 1)
			Expect(err).To(BeNil())
			Expect(len(alerts)).To(Equal(0))
		})

		It("should allow egress after kubearmor-network-posture annotation is removed", func() {
			_, err := Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
			Expect(err).To(BeNil())

			DeferCleanup(func() {
				_, _ = Kubectl("annotate ns nginx-posture kubearmor-network-posture=block --overwrite")
			})

			netBin, netArgs := probeNetworkBinary(ng, "nginx-posture")
			if netBin == "" {
				Skip("No network binary found in pod " + ng)
			}

			_, err = Kubectl("annotate ns nginx-posture kubearmor-network-posture-")
			Expect(err).To(BeNil())

			time.Sleep(5 * time.Second)

			AssertCommand(
				ng, "nginx-posture", netArgs,
				Not(MatchRegexp(`(?i)(permission denied|operation not permitted)`)),
				false,
			)
		})
	})
})
