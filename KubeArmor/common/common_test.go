// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsUnsafePathToRemove(t *testing.T) {
	unsafePaths := []string{
		"",
		"   ",
		".",
		"..",
		"/",
		string(filepath.Separator),
	}

	vol := filepath.VolumeName(os.Getenv("SystemDrive"))
	if vol != "" {
		unsafePaths = append(unsafePaths, vol, vol+string(filepath.Separator))
	}

	for _, p := range unsafePaths {
		if !isUnsafePathToRemove(p) {
			t.Errorf("expected path %q to be marked unsafe, but got safe", p)
		}
		if err := RemoveSafe(p); err != errUnsafePathToRemove {
			t.Errorf("expected RemoveSafe(%q) to fail with errUnsafePathToRemove, got: %v", p, err)
		}
		if err := RemoveAllSafe(p); err != errUnsafePathToRemove {
			t.Errorf("expected RemoveAllSafe(%q) to fail with errUnsafePathToRemove, got: %v", p, err)
		}
	}
}

func TestRemoveSafe_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to create temp test file: %v", err)
	}

	if err := RemoveSafe(testFile); err != nil {
		t.Errorf("expected RemoveSafe to succeed on valid file, got: %v", err)
	}

	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Errorf("expected test file to be removed")
	}
}

func TestRemoveAllSafe_ValidDir(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")

	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("failed to create temp subdir: %v", err)
	}

	if err := RemoveAllSafe(subDir); err != nil {
		t.Errorf("expected RemoveAllSafe to succeed on valid directory, got: %v", err)
	}

	if _, err := os.Stat(subDir); !os.IsNotExist(err) {
		t.Errorf("expected subdir to be removed")
	}
}
