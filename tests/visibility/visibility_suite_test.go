// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package visibility_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestVisibility(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Visibility Suite")
}
