// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package configmap_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKubearmorConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KubearmorConfig Suite")
}
