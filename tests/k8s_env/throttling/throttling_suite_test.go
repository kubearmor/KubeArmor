// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package throttling_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestThrottling(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Throttling Suite")
}
