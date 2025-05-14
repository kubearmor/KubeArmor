// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor
package networktests_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNetworktests(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Networktests Suite")
}
