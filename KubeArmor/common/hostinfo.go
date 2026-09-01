// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

// Platform-specific host/system information helpers live in hostinfo_<goos>.go.
// Every one of those files MUST provide the same set of exported functions so the
// rest of KubeArmor can call them without any build-tag awareness:
//
//	GetOSImage() string                  // "<name> <version>", "" if unknown
//	GetMachineID(extraPaths ...string) string // stable host id, "" if unknown
//	GetBootTime() string                 // boot time, UTC, truncated to the second; "" if unknown
//	GetSupportedLSMs() string            // kernel active-LSM list, "" if none / not exposed
//	GetUptimeTimestamp() float64         // boot time as fractional unix seconds (anchor for boot-relative event ts)
//
// Selection is by the implicit GOOS filename suffix. hostinfo_other.go carries an
// explicit "!linux && !darwin && !windows" constraint so the package keeps building
// on any other GOOS. When adding Windows (or another OS) support, add one more
// hostinfo_<goos>.go implementing the contract above.

import (
	"os"
	"path/filepath"
	"strings"
)

// readFirstNonEmptyFile returns the trimmed content of the first path that exists
// and is non-empty, or "" if none qualify. Empty path entries are skipped.
func readFirstNonEmptyFile(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if b, err := os.ReadFile(filepath.Clean(p)); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}
