// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShortSha(t *testing.T) {
	var_run_containerd_containerd_sha := ShortSHA("var_run_containerd_containerd.sock")
	assert.Equal(t, "fe19b", var_run_containerd_containerd_sha)

	run_crio_crio_sha := ShortSHA("run_crio_crio.sock")
	assert.Equal(t, "04ac6", run_crio_crio_sha)
}
