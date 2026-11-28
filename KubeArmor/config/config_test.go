// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package config

import "testing"

func TestValidMaxRulesPerContainer(t *testing.T) {
	for in, want := range map[int]uint32{
		0:                           DefaultMaxRulesPerContainer,
		-1:                          DefaultMaxRulesPerContainer,
		1:                           1,
		1024:                        1024,
		MaxMaxRulesPerContainer:     MaxMaxRulesPerContainer,
		MaxMaxRulesPerContainer + 1: DefaultMaxRulesPerContainer,
	} {
		if got := validMaxRulesPerContainer(in); got != want {
			t.Errorf("validMaxRulesPerContainer(%d) = %d, want %d", in, got, want)
		}
	}
}
