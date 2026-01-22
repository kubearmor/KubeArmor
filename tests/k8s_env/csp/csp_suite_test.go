// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package csp_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCsp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Csp Suite")
}
