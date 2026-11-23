//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindHomeDirFromPasswd_FileNotFound(t *testing.T) {
	// Must not panic and must return an empty string when the file does not exist.
	got := findHomeDirFromPasswd("/nonexistent/passwd/path")
	if got != "" {
		t.Errorf("expected empty string for nonexistent file, got %q", got)
	}
}

func TestFindHomeDirFromPasswd_MalformedEntries(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "passwd-malformed-*")
	if err != nil {
		t.Fatalf("failed to create temp passwd file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
# comment line
invalid
foo:bar:baz
user:x:1000:1000
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp passwd file: %v", err)
	}
	_ = tmpFile.Close()

	got := findHomeDirFromPasswd(tmpFile.Name())
	if got != "" {
		t.Errorf("expected empty string for malformed entries, got %q", got)
	}
}

func TestFindHomeDirFromPasswd_Success(t *testing.T) {
	tempHomeDir, err := os.MkdirTemp("", "user-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home dir: %v", err)
	}
	defer os.RemoveAll(tempHomeDir)

	storagePath := filepath.Join(tempHomeDir, ".local/share/containers/storage/overlay-containers")
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		t.Fatalf("failed to create overlay-containers dir: %v", err)
	}

	containersFile := filepath.Join(storagePath, "containers.json")
	if err := os.WriteFile(containersFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to create containers.json: %v", err)
	}

	tmpPasswd, err := os.CreateTemp("", "passwd-success-*")
	if err != nil {
		t.Fatalf("failed to create temp passwd file: %v", err)
	}
	defer os.Remove(tmpPasswd.Name())

	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"other:x:1001:1001:Other:/nonexistent/home:/bin/false\n" +
		"testuser:x:1000:1000:Test User:" + tempHomeDir + ":/bin/bash\n"

	if _, err := tmpPasswd.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp passwd file: %v", err)
	}
	_ = tmpPasswd.Close()

	got := findHomeDirFromPasswd(tmpPasswd.Name())
	if got != tempHomeDir {
		t.Errorf("expected %q, got %q", tempHomeDir, got)
	}
}
