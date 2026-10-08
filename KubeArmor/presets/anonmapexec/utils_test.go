// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package anonmapexec

import "testing"

// ── ParseProtectionFlags ──────────────────────────────────────────────────────

func TestParseProtectionFlags(t *testing.T) {
	tests := []struct {
		name     string
		prot     uint64
		expected string
	}{
		{"zero_flags", 0x0, ""},
		{"read_only", 0x1, "PROT_READ"},
		{"write_only", 0x2, "PROT_WRITE"},
		{"exec_only", 0x4, "PROT_EXEC"},
		{"read_write", 0x3, "PROT_READ|PROT_WRITE"},
		{"read_exec", 0x5, "PROT_READ|PROT_EXEC"},
		{"write_exec", 0x6, "PROT_WRITE|PROT_EXEC"},
		{"all_flags", 0x7, "PROT_READ|PROT_WRITE|PROT_EXEC"},
		{"high_bits_ignored", 0xFF, "PROT_READ|PROT_WRITE|PROT_EXEC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseProtectionFlags(tt.prot)
			if got != tt.expected {
				t.Errorf("ParseProtectionFlags(0x%x) = %q, want %q", tt.prot, got, tt.expected)
			}
		})
	}
}

// ── ParseMemoryFlags ──────────────────────────────────────────────────────────

func TestParseMemoryFlags(t *testing.T) {
	tests := []struct {
		name     string
		flag     uint64
		expected string
	}{
		{"zero_flags", 0x0, ""},
		{"shared_only", 0x01, "MAP_SHARED"},
		{"private_only", 0x02, "MAP_PRIVATE"},
		{"fixed_only", 0x10, "MAP_FIXED"},
		{"anonymous_only", 0x20, "MAP_ANONYMOUS"},
		{"growsdown_only", 0x1000, "MAP_GROWSDOWN"},
		{"denywrite_only", 0x0800, "MAP_DENYWRITE"},
		{"shared_anonymous", 0x21, "MAP_SHARED|MAP_ANONYMOUS"},
		{"private_anonymous", 0x22, "MAP_PRIVATE|MAP_ANONYMOUS"},
		{"private_fixed_anonymous", 0x32, "MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS"},
		{
			"all_flags",
			0x01 | 0x02 | 0x10 | 0x20 | 0x1000 | 0x0800,
			"MAP_SHARED|MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_DENYWRITE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseMemoryFlags(tt.flag)
			if got != tt.expected {
				t.Errorf("ParseMemoryFlags(0x%x) = %q, want %q", tt.flag, got, tt.expected)
			}
		})
	}
}
