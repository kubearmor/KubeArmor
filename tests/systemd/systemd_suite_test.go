// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package systemd_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"testing"
)

func TestSystemd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Systemd Suite")
}
