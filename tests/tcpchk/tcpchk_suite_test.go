// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package tcpchk_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTcpchk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tcpchk Suite")
}
