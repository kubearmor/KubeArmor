// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestMatchExpIdentities(t *testing.T) {
	const (
		ns  = "namespaceName=multiubuntu"
		c1  = "container=ubuntu-1"
		c2  = "container=ubuntu-2"
		c3  = "container=ubuntu-3"
	)

	tests := []struct {
		name            string
		identities      []string
		nonIdentities   []string
		superIdentities []string
		want            bool
	}{
		{
			name:            "no requirements selects everything",
			superIdentities: []string{ns, c1},
			want:            true,
		},
		{
			name:            "In is satisfied",
			identities:      []string{c1},
			superIdentities: []string{ns, c1},
			want:            true,
		},
		{
			name:            "In alone is enforced",
			identities:      []string{c1},
			superIdentities: []string{ns, c2},
			want:            false,
		},
		{
			name:            "NotIn excludes a match",
			nonIdentities:   []string{c3},
			superIdentities: []string{ns, c3},
			want:            false,
		},
		{
			name:            "NotIn alone admits a non-match",
			nonIdentities:   []string{c3},
			superIdentities: []string{ns, c1},
			want:            true,
		},
		{
			name:            "In and NotIn both satisfied",
			identities:      []string{c1},
			nonIdentities:   []string{c3},
			superIdentities: []string{ns, c1},
			want:            true,
		},
		{
			name:            "NotIn matches so In cannot rescue it",
			identities:      []string{c3},
			nonIdentities:   []string{c3},
			superIdentities: []string{ns, c3},
			want:            false,
		},
		{
			// The two requirements are ANDed, so a failed In stands even when
			// no NotIn value is present.
			name:            "In fails while NotIn is clear",
			identities:      []string{c1},
			nonIdentities:   []string{c3},
			superIdentities: []string{ns, c2},
			want:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selector := tp.SelectorType{
				MatchExpIdentities: tt.identities,
				NonIdentities:      tt.nonIdentities,
			}
			if got := MatchExpIdentities(selector, tt.superIdentities); got != tt.want {
				t.Errorf("MatchExpIdentities() = %v, want %v", got, tt.want)
			}
		})
	}
}
