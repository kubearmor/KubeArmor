// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package host_policy_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHostPolicy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Host Policy Test Suite")
}
