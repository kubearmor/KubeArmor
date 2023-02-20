// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package systemd

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os/exec"
	"strings"
	"time"
)

var _ = Describe("systemd", func() {
	It("should be installed on the system", func() {
		out, err := exec.LookPath("kubearmor")
		Expect(err).NotTo(HaveOccurred(), "kubearmor is not installed on the system")
		fmt.Printf("OUTPUT of is in path: %s\n", string(out))
	})

	It("should be running on the system", func() {
		out, err := exec.Command("systemctl", "is-active", "kubearmor").Output()
		Expect(err).NotTo(HaveOccurred(), "failed to check if kubearmor is running")
		Expect(string(out)).To(Equal("active\n"), "kubearmor is not running")
		fmt.Printf("OUTPUT of is alive: %s\n", string(out))
	})

	It("it should implement policy", func() {
		out, err := exec.Command("sudo", "karmor", "vm", "policy", "add", "manifests/hostpolicy.yaml").Output()
		Expect(err).NotTo(HaveOccurred(), "failed to add policy")
		fmt.Printf("OUTPUT of implement policy: %s\n", string(out))
	})

	time.Sleep(5 * time.Second)

	It("it should block sleep", func() {
		_, err := exec.Command("sleep", "1").Output()
		denied := strings.Contains(err.Error(), "permission denied")
		Expect(denied).To(Equal(true), "policy blocked sleep successfullly")
		fmt.Printf("OUTPUT of policy blocked: %s\n", err.Error())
	})

})
