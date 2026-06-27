// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package kubearmor_self_protection_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKubeArmorSelfProtection(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KubeArmor Self-Protection Suite")
}
