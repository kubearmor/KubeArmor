// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

// Package common contains tests for the utility functions in the common package.
// The internal package declaration (rather than common_test) is intentional:
// it allows direct access to the unexported errUnsafePathToRemove sentinel
// used in TestRemoveSafe and TestRemoveAllSafe.
package common

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// TestParseURL — tests the ParseURL function
// =============================================================================

func TestParseURL(t *testing.T) {
	t.Log("[INFO] Testing ParseURL")

	tests := []struct {
		name      string
		address   string
		wantHost  string
		wantPort  string
		wantError bool
	}{
		// --- Happy path: full URL with scheme and port ---
		{
			name:     "full URL with http scheme and port",
			address:  "http://localhost:8080",
			wantHost: "localhost",
			wantPort: "8080",
		},
		{
			name:     "full URL with https scheme and port",
			address:  "https://kubearmor.io:443",
			wantHost: "kubearmor.io",
			wantPort: "443",
		},
		// --- Schemeless input with port ---
		{
			name:     "host and port without scheme",
			address:  "localhost:32767",
			wantHost: "localhost",
			wantPort: "32767",
		},
		// --- No port: should default to "80" ---
		{
			name:     "full URL with scheme but no port",
			address:  "http://kubearmor.io",
			wantHost: "kubearmor.io",
			wantPort: "80",
		},
		{
			name:     "hostname only without scheme or port",
			address:  "kubearmor.io",
			wantHost: "kubearmor.io",
			wantPort: "80",
		},
		// --- IPv4 address ---
		{
			name:     "IPv4 address with port and scheme",
			address:  "http://192.168.1.1:9090",
			wantHost: "192.168.1.1",
			wantPort: "9090",
		},
		{
			name:     "IPv4 address with port but no scheme",
			address:  "192.168.1.1:9090",
			wantHost: "192.168.1.1",
			wantPort: "9090",
		},
		// --- Edge cases that don't error but return empty host ---
		{
			name:     "completely invalid URL format",
			address:  "://not-a-url",
			wantHost: "",
			wantPort: "80",
		},
		{
			name:     "empty string",
			address:  "",
			wantHost: "",
			wantPort: "80",
		},
		// --- True error cases ---
		{
			name:      "control characters cause parse error",
			address:   "http://foo\x00bar",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := ParseURL(tc.address)

			if tc.wantError {
				if err == nil {
					t.Errorf("[FAIL] expected error for address %q, got host=%q port=%q",
						tc.address, host, port)
				}
				return
			}

			if err != nil {
				t.Errorf("[FAIL] unexpected error for address %q: %v", tc.address, err)
				return
			}
			if host != tc.wantHost {
				t.Errorf("[FAIL] host mismatch for address %q: got %q, want %q",
					tc.address, host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("[FAIL] port mismatch for address %q: got %q, want %q",
					tc.address, port, tc.wantPort)
			}
		})
	}
}

// =============================================================================
// TestClone — tests the Clone function
// =============================================================================

type cloneTestStruct struct {
	Name  string   `json:"name"`
	Value int      `json:"value"`
	Tags  []string `json:"tags"`
}

func TestClone(t *testing.T) {
	t.Log("[INFO] Testing Clone")

	t.Run("clone struct to identical struct", func(t *testing.T) {
		src := cloneTestStruct{Name: "kubearmor", Value: 42, Tags: []string{"a", "b"}}
		var dst cloneTestStruct

		if err := Clone(src, &dst); err != nil {
			t.Errorf("[FAIL] Clone returned unexpected error: %v", err)
			return
		}
		if dst.Name != src.Name {
			t.Errorf("[FAIL] Name mismatch: got %q, want %q", dst.Name, src.Name)
		}
		if dst.Value != src.Value {
			t.Errorf("[FAIL] Value mismatch: got %d, want %d", dst.Value, src.Value)
		}
		if len(dst.Tags) != len(src.Tags) {
			t.Errorf("[FAIL] Tags length mismatch: got %d, want %d", len(dst.Tags), len(src.Tags))
			return
		}
		for i, tag := range src.Tags {
			if dst.Tags[i] != tag {
				t.Errorf("[FAIL] Tags[%d] mismatch: got %q, want %q", i, dst.Tags[i], tag)
			}
		}
		t.Log("[PASS] Clone struct to identical struct")
	})

	t.Run("clone produces independent copy", func(t *testing.T) {
		src := cloneTestStruct{Name: "original", Value: 1, Tags: []string{"x"}}
		var dst cloneTestStruct
		if err := Clone(src, &dst); err != nil {
			t.Errorf("[FAIL] Clone returned unexpected error: %v", err)
			return
		}
		// Mutate dst and confirm src is unchanged
		dst.Name = "modified"
		dst.Tags[0] = "y"
		if src.Name != "original" {
			t.Errorf("[FAIL] Clone is not independent: src.Name was mutated to %q", src.Name)
		}
		t.Log("[PASS] Clone produces independent copy")
	})

	t.Run("clone with nil pointer source produces zero dst", func(t *testing.T) {
		var src *cloneTestStruct
		var dst cloneTestStruct
		// Marshal of nil pointer produces "null"; Unmarshal of "null" into struct is a no-op, err=nil.
		if err := Clone(src, &dst); err != nil {
			t.Errorf("[FAIL] Clone of nil pointer returned unexpected error: %v", err)
		}
		t.Log("[PASS] Clone of nil pointer")
	})

	t.Run("clone with non-pointer dst returns error", func(t *testing.T) {
		src := cloneTestStruct{Name: "test"}
		var dst cloneTestStruct
		// Passing non-pointer dst causes json.Unmarshal to return an error.
		err := Clone(src, dst) // dst is NOT a pointer
		if err == nil {
			t.Errorf("[FAIL] expected error when dst is not a pointer, got nil")
		}
		t.Log("[PASS] Clone with non-pointer dst returns error")
	})
}

// =============================================================================
// TestRemoveSafe — tests the RemoveSafe function
// =============================================================================

func TestRemoveSafe(t *testing.T) {
	t.Log("[INFO] Testing RemoveSafe")

	t.Run("empty path returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveSafe("")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove, got: %v", err)
			return
		}
		t.Log("[PASS] Empty path blocked")
	})

	t.Run("root path '/' returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveSafe("/")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove for '/', got: %v", err)
			return
		}
		t.Log("[PASS] Root path '/' blocked")
	})

	t.Run("path that cleans to root returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveSafe("//..//")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove for '//..//', got: %v", err)
			return
		}
		t.Log("[PASS] Path cleaning to '/' blocked")
	})

	t.Run("non-existent safe path returns os error not sentinel", func(t *testing.T) {
		path := filepath.Join(os.TempDir(), "kubearmor_test_removesafe_nonexistent")
		err := RemoveSafe(path)
		if errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] non-existent safe path should not return errUnsafePathToRemove")
			return
		}
		// err should be an *os.PathError because the file doesn't exist.
		if err == nil {
			t.Errorf("[FAIL] expected an os error for non-existent path, got nil")
			return
		}
		t.Log("[PASS] Non-existent path returns os error, not sentinel")
	})

	t.Run("existing file is removed successfully", func(t *testing.T) {
		// Create a real temp file to test actual removal.
		f, err := os.CreateTemp("", "kubearmor_test_removesafe_*")
		if err != nil {
			t.Fatalf("[FAIL] could not create temp file: %v", err)
		}
		path := f.Name()
		defer os.Remove(path)
		f.Close()

		if err := RemoveSafe(path); err != nil {
			t.Errorf("[FAIL] RemoveSafe on existing file returned error: %v", err)
			return
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("[FAIL] file still exists after RemoveSafe: %s", path)
		}
		t.Log("[PASS] Existing file removed successfully")
	})
}

// =============================================================================
// TestRemoveAllSafe — tests the RemoveAllSafe function
// =============================================================================

func TestRemoveAllSafe(t *testing.T) {
	t.Log("[INFO] Testing RemoveAllSafe")

	t.Run("empty path returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveAllSafe("")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove, got: %v", err)
			return
		}
		t.Log("[PASS] Empty path blocked")
	})

	t.Run("root path '/' returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveAllSafe("/")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove for '/', got: %v", err)
			return
		}
		t.Log("[PASS] Root path '/' blocked")
	})

	t.Run("path that cleans to root returns errUnsafePathToRemove", func(t *testing.T) {
		err := RemoveAllSafe("///..//")
		if !errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] expected errUnsafePathToRemove for '///..//', got: %v", err)
			return
		}
		t.Log("[PASS] Path cleaning to '/' blocked")
	})

	t.Run("non-existent safe path returns nil (os.RemoveAll is idempotent)", func(t *testing.T) {
		path := filepath.Join(os.TempDir(), "kubearmor_test_removeallsafe_nonexistent_dir")
		err := RemoveAllSafe(path)
		if errors.Is(err, errUnsafePathToRemove) {
			t.Errorf("[FAIL] non-existent safe path should not return errUnsafePathToRemove")
			return
		}
		// os.RemoveAll on a non-existent path returns nil — this is idempotent by design.
		if err != nil {
			t.Errorf("[FAIL] RemoveAllSafe on non-existent path should return nil, got: %v", err)
		}
		t.Log("[PASS] Non-existent path returns nil (idempotent)")
	})

	t.Run("existing directory tree is removed successfully", func(t *testing.T) {
		// Create a temp directory with nested content.
		dir, err := os.MkdirTemp("", "kubearmor_test_removeallsafe_*")
		if err != nil {
			t.Fatalf("[FAIL] could not create temp dir: %v", err)
		}
		defer os.RemoveAll(dir)
		// Create a file inside to test recursive removal.
		inner := filepath.Join(dir, "innerfile.txt")
		if err := os.WriteFile(inner, []byte("test"), 0600); err != nil {
			t.Fatalf("[FAIL] could not create inner file: %v", err)
		}

		if err := RemoveAllSafe(dir); err != nil {
			t.Errorf("[FAIL] RemoveAllSafe on existing dir returned error: %v", err)
			return
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("[FAIL] directory still exists after RemoveAllSafe: %s", dir)
		}
		t.Log("[PASS] Directory tree removed successfully")
	})
}
