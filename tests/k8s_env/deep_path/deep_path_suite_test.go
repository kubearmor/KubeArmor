// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package deep_path_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDeepPath(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Deep Path Suite")
}
