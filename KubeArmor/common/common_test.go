// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"slices"
	"strings"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// sortByName mirrors how callers normalize a host policy slice before hashing,
// so these tests exercise the documented "pre-sort your slices" contract.
func sortByName(in []tp.HostSecurityPolicy) []tp.HostSecurityPolicy {
	out := make([]tp.HostSecurityPolicy, len(in))
	copy(out, in)
	slices.SortStableFunc(out, func(a, b tp.HostSecurityPolicy) int {
		return strings.Compare(a.Metadata["policyName"], b.Metadata["policyName"])
	})
	return out
}

func policy(name string) tp.HostSecurityPolicy {
	return tp.HostSecurityPolicy{Metadata: map[string]string{"policyName": name}}
}

func TestComputeHash_DeterministicForEqualInput(t *testing.T) {
	in := []tp.HostSecurityPolicy{policy("alpha"), policy("beta")}

	h1, err := ComputeHash(in)
	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}
	h2, err := ComputeHash(in)
	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected identical hashes, got %s vs %s", h1, h2)
	}
}

func TestComputeHash_OrderIndependentAfterSort(t *testing.T) {
	one := sortByName([]tp.HostSecurityPolicy{policy("alpha"), policy("beta")})
	two := sortByName([]tp.HostSecurityPolicy{policy("beta"), policy("alpha")})

	h1, _ := ComputeHash(one)
	h2, _ := ComputeHash(two)
	if h1 != h2 {
		t.Fatalf("sorted permutations must hash identically, got %s vs %s", h1, h2)
	}
}

func TestComputeHash_DifferentContentDifferentHash(t *testing.T) {
	h1, _ := ComputeHash([]tp.HostSecurityPolicy{policy("alpha")})
	h2, _ := ComputeHash([]tp.HostSecurityPolicy{policy("alpha-modified")})
	if h1 == h2 {
		t.Fatalf("different content must produce different hashes, both were %s", h1)
	}
}

func TestComputeHash_EmptyIsStableNonEmptySentinel(t *testing.T) {
	h1, _ := ComputeHash([]tp.HostSecurityPolicy{})
	h2, _ := ComputeHash([]tp.HostSecurityPolicy{})
	if h1 != h2 {
		t.Fatalf("empty inputs must hash identically: %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Fatalf("empty input must still produce a non-empty hash")
	}
}

func TestComputeHash_HexLengthIsSHA256(t *testing.T) {
	h, err := ComputeHash("anything")
	if err != nil {
		t.Fatalf("ComputeHash failed: %v", err)
	}
	if len(h) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Fatalf("expected 64-char hex digest, got %d chars: %s", len(h), h)
	}
}
