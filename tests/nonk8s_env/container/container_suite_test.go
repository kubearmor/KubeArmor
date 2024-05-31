// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
// test

package container_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestContainerProtection(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Container Protection Suite")
}
