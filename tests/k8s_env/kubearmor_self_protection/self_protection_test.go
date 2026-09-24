// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package kubearmor_self_protection_test

import (
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const kubearmorNS = "kubearmor"

var auditPolicyFiles = []string{
	"res/namespace-posture-audit.yaml",
	"res/ksp-kubearmor-daemon-main-audit.yaml",
	"res/ksp-kubearmor-daemon-init-audit.yaml",
}

func kubearmorInstalled() bool {
	out, err := Kubectl(fmt.Sprintf("get ns %s", kubearmorNS))
	return err == nil && strings.Contains(out, kubearmorNS)
}

func kubearmorDaemonRunning() bool {
	pods, err := K8sGetPods("kubearmor", kubearmorNS, []string{"kubearmor-app=kubearmor"}, 0)
	return err == nil && len(pods) > 0
}

var _ = Describe("KubeArmor self-protection policies", func() {

	BeforeEach(func() {
		if !kubearmorInstalled() {
			Skip("kubearmor namespace not found — install KubeArmor before running this suite")
		}
	})

	AfterEach(func() {
		for i := len(auditPolicyFiles) - 1; i >= 0; i-- {
			_, _ = Kubectl(fmt.Sprintf("delete -f %s --ignore-not-found", auditPolicyFiles[i]))
		}
	})

	It("applies audit-phase policy manifests successfully", func() {
		for _, f := range auditPolicyFiles {
			err := K8sApplyFile(f)
			Expect(err).To(BeNil())
		}
	})

	It("keeps kubearmor daemon pods healthy after audit policies are applied", func() {
		if !kubearmorDaemonRunning() {
			Skip("no KubeArmor daemon pods in namespace kubearmor — deploy KubeArmor before running pod health checks")
		}

		for _, f := range auditPolicyFiles {
			err := K8sApplyFile(f)
			Expect(err).To(BeNil())
		}

		time.Sleep(30 * time.Second)

		pods, err := K8sGetPods("kubearmor", kubearmorNS, []string{"kubearmor-app=kubearmor"}, 120)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(BeNumerically(">", 0))
	})

	It("applies block policies when KUBEARMOR_SELF_PROTECTION_BLOCK_TEST=1", func() {
		if os.Getenv("KUBEARMOR_SELF_PROTECTION_BLOCK_TEST") != "1" {
			Skip("set KUBEARMOR_SELF_PROTECTION_BLOCK_TEST=1 with PR1 merged and selfProtection.enabled=true")
		}
		if !kubearmorDaemonRunning() {
			Skip("no KubeArmor daemon pods in namespace kubearmor — deploy KubeArmor before running block enforcement checks")
		}

		blockFiles := []string{
			"res/namespace-posture-block.yaml",
			"res/ksp-kubearmor-daemon-main-block.yaml",
			"res/ksp-kubearmor-daemon-init-block.yaml",
			"res/ksp-kubearmor-daemon-admin-tools-block.yaml",
		}

		for _, f := range blockFiles {
			err := K8sApplyFile(f)
			Expect(err).To(BeNil())
		}

		time.Sleep(30 * time.Second)

		pods, err := K8sGetPods("kubearmor", kubearmorNS, []string{"kubearmor-app=kubearmor"}, 120)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(BeNumerically(">", 0))

		for _, f := range blockFiles {
			_, _ = Kubectl(fmt.Sprintf("delete -f %s --ignore-not-found", f))
		}
	})
})
