// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package hostsecurity_test

import (
    "testing"

    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestHostSecurity(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "Host Security Suite")
}
