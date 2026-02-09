// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package nsp

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/protobuf"
	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {

	// delete all NSPs
	err := DeleteAllNsp()
	Expect(err).To(BeNil())
})

var _ = Describe("NSP", func() {

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllNsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(5 * time.Second)
	})

	Describe("Egress", func() {
		It("can drop outgoing DNS packets", func() {

			// Being root user is a must to use nft command
			// Since kubearmor does not run as root when using ubi image, we skip this test
			if strings.Contains(K8sRuntimeEnforcer(), "bpf") {
				Skip("Skipping due to root user requirement for nft")
			}

			// Apply policy
			err := K8sApplyFile("res/nsp-egress-block-dns.yaml")
			Expect(err).To(BeNil())

			// wait for policy creation, added due to flaky behaviour
			time.Sleep(10 * time.Second)

			// Start Kubearmor Logs
			err = KarmorLogStart("policy", "", "NetworkFirewall", "")
			Expect(err).To(BeNil())

			// check udp connection to 1.1.1.1:53, and wait for max 2 seconds
			cmd := exec.Command("nc", "-uvz", "-w", "2", "1.1.1.1", "53")
			sout, err := cmd.Output()
			if err != nil {
				fmt.Printf("Error: %v", err)
			}
			fmt.Printf("Output: %s", string(sout))

			expect := protobuf.Alert{
				PolicyName: "nsp-egress-block-dns",
				Severity:   "5",
				Action:     "Block",
			}

			// check policy alert
			res, err := KarmorGetTargetAlert(5*time.Second, &expect)
			Expect(err).To(BeNil())
			Expect(res.Found).To(BeTrue())
		})
	})

})
