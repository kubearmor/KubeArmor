// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import "testing"

func TestProcessExitData(t *testing.T) {
	tests := []struct {
		name string
		code int64 // do_exit() argument, in wait-status format
		want string
	}{
		{"exit 0", 0, "kprobe=do_exit exitCode=0 signal=0"},
		{"exit 3", 3 << 8, "kprobe=do_exit exitCode=3 signal=0"},
		{"exit 255", 255 << 8, "kprobe=do_exit exitCode=255 signal=0"},
		{"killed by SIGKILL", 9, "kprobe=do_exit exitCode=0 signal=9"},
		{"SIGSEGV with core dump", 11 | 0x80, "kprobe=do_exit exitCode=0 signal=11 coreDumped=true"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := processExitData(tc.code); got != tc.want {
				t.Fatalf("processExitData(%#x) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}
