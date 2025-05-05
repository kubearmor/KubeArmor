// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package hsp_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHsp(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hsp Suite")
}
