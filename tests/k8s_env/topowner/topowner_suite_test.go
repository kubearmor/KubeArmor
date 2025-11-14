// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor

package cronjobjobpod_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCronJobJobPodSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KubeArmor CronJob/Job/Pod Suite")
}
