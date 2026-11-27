// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"errors"
	"testing"
	"time"
)

// fakeMonotonic makes monotonicNowNs return a fixed value for the test
func fakeMonotonic(t *testing.T, nowNs int64, err error) {
	t.Helper()
	orig := monotonicNowNs
	monotonicNowNs = func() (int64, error) { return nowNs, err }
	t.Cleanup(func() { monotonicNowNs = orig })
}

func parseUpdatedTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(TimeFormUTC, s)
	if err != nil {
		t.Fatalf("UpdatedTime %q is not in TimeFormUTC: %v", s, err)
	}
	return ts
}

func assertNear(t *testing.T, got, want time.Time, tolerance time.Duration) {
	t.Helper()
	if d := got.Sub(want); d > tolerance || d < -tolerance {
		t.Fatalf("got %s, want %s (±%s), off by %s", got, want, tolerance, d)
	}
}

func TestGetDateTimeFromKernelTime(t *testing.T) {
	const mono = int64(1_000 * time.Second) // monotonic "now": 1000s since boot
	const tolerance = 100 * time.Millisecond

	tests := []struct {
		name    string
		ktime   uint64
		monoErr error
		ago     time.Duration // expected: event happened this long before now
	}{
		{"event 2.5s ago", uint64(mono - int64(2500*time.Millisecond)), nil, 2500 * time.Millisecond},
		{"event now", uint64(mono), nil, 0},
		{"no kernel time falls back to now", 0, nil, 0},
		{"event in the future is clamped to now", uint64(mono + int64(time.Second)), nil, 0},
		{"monotonic clock error falls back to now", uint64(mono - int64(time.Second)), errors.New("no clock"), 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeMonotonic(t, mono, tc.monoErr)

			sec, updated := GetDateTimeFromKernelTime(tc.ktime)
			want := time.Now().UTC().Add(-tc.ago)

			got := parseUpdatedTime(t, updated)
			assertNear(t, got, want, tolerance)
			if sec != got.Unix() {
				t.Fatalf("Timestamp %d does not match UpdatedTime %s", sec, updated)
			}
		})
	}
}

// Events must keep their kernel order even if they are converted (processed)
// in a different order, which is the reason for using the kernel time.
func TestGetDateTimeFromKernelTimeKeepsKernelOrder(t *testing.T) {
	const mono = int64(500 * time.Second)
	fakeMonotonic(t, mono, nil)

	first := uint64(mono - int64(3*time.Millisecond))  // happened first
	second := uint64(mono - int64(1*time.Millisecond)) // happened 2ms later

	// processed in reverse order
	_, secondStr := GetDateTimeFromKernelTime(second)
	_, firstStr := GetDateTimeFromKernelTime(first)

	if !parseUpdatedTime(t, firstStr).Before(parseUpdatedTime(t, secondStr)) {
		t.Fatalf("kernel order lost: first=%s second=%s", firstStr, secondStr)
	}
}

// Sanity check against the real CLOCK_MONOTONIC (the clock of bpf_ktime_get_ns).
func TestGetDateTimeFromKernelTimeRealClock(t *testing.T) {
	monoNow, err := monotonicNowNs()
	if err != nil {
		t.Skipf("CLOCK_MONOTONIC not available: %v", err)
	}

	_, updated := GetDateTimeFromKernelTime(uint64(monoNow - int64(time.Second)))
	assertNear(t, parseUpdatedTime(t, updated), time.Now().UTC().Add(-time.Second), 100*time.Millisecond)
}
