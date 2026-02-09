// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package nsp_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNsp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Nsp Suite")
}
