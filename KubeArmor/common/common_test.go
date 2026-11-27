// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestMatchExpIdentitiesInAndNotIn(t *testing.T) {
	tests := []struct {
		name           string
		selector       tp.SelectorType
		identities     []string
		expectedResult bool
	}{
		{
			name: "In matches and NotIn does not exclude",
			selector: tp.SelectorType{
				MatchExpIdentities: []string{"container=ubuntu-1"},
				NonIdentities:      []string{"container=ubuntu-3"},
			},
			identities:     []string{"container=ubuntu-1"},
			expectedResult: true,
		},
		{
			name: "In does not match and NotIn does not exclude",
			selector: tp.SelectorType{
				MatchExpIdentities: []string{"container=ubuntu-1"},
				NonIdentities:      []string{"container=ubuntu-3"},
			},
			identities:     []string{"container=ubuntu-2"},
			expectedResult: false,
		},
		{
			name: "In matches but NotIn excludes",
			selector: tp.SelectorType{
				MatchExpIdentities: []string{"container=ubuntu-1"},
				NonIdentities:      []string{"container=ubuntu-3"},
			},
			identities:     []string{"container=ubuntu-1", "container=ubuntu-3"},
			expectedResult: false,
		},
		{
			name: "only NotIn and no exclusion",
			selector: tp.SelectorType{
				NonIdentities: []string{"container=ubuntu-3"},
			},
			identities:     []string{"container=ubuntu-2"},
			expectedResult: true,
		},
		{
			name: "only NotIn and excluded",
			selector: tp.SelectorType{
				NonIdentities: []string{"container=ubuntu-3"},
			},
			identities:     []string{"container=ubuntu-3"},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchExpIdentities(tt.selector, tt.identities); got != tt.expectedResult {
				t.Errorf("MatchExpIdentities() = %v, want %v", got, tt.expectedResult)
			}
		})
	}
}
