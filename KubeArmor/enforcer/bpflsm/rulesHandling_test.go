// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"strings"
	"testing"
)

func TestMakeInnerKeyWithPath(t *testing.T) {
	pathStr := "/etc/config.conf"
	key := makeInnerKey(pathStr, "")

	// Verify KeyType is set to 1 (inode-based key)
	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	// Verify path is copied to Path field
	pathField := string(key.Path[:])
	if !strings.HasPrefix(pathField, pathStr) {
		maxLen := len(pathStr)
		if len(pathField) < maxLen {
			maxLen = len(pathField)
		}
		t.Errorf("Expected Path to start with %s, got %s", pathStr, pathField[:maxLen])
	}

	sourceField := strings.TrimRight(string(key.Source[:]), "\x00")
	if sourceField != "" {
		t.Errorf("Expected empty Source, got %s", sourceField)
	}

	// Inode/device fields should be 0 in userspace
	if key.Ino != 0 {
		t.Errorf("Expected Ino=0 in userspace, got %d", key.Ino)
	}
	if key.Dev != 0 {
		t.Errorf("Expected Dev=0 in userspace, got %d", key.Dev)
	}
}

func TestMakeInnerKeyWithPathAndSource(t *testing.T) {
	pathStr := "/usr/bin/curl"
	srcStr := "/home/user/app"

	key := makeInnerKey(pathStr, srcStr)

	// Verify KeyType is set
	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathField := string(key.Path[:])
	if !strings.HasPrefix(pathField, pathStr) {
		maxLen := len(pathStr)
		if len(pathField) < maxLen {
			maxLen = len(pathField)
		}
		t.Errorf("Expected Path to start with %s, got %s", pathStr, pathField[:maxLen])
	}

	sourceField := string(key.Source[:])
	if !strings.HasPrefix(sourceField, srcStr) {
		maxLen := len(srcStr)
		if len(sourceField) < maxLen {
			maxLen = len(sourceField)
		}
		t.Errorf("Expected Source to start with %s, got %s", srcStr, sourceField[:maxLen])
	}

	if key.Ino != 0 {
		t.Errorf("Expected Ino=0 in userspace, got %d", key.Ino)
	}
	if key.Dev != 0 {
		t.Errorf("Expected Dev=0 in userspace, got %d", key.Dev)
	}
	if key.SrcIno != 0 {
		t.Errorf("Expected SrcIno=0 in userspace, got %d", key.SrcIno)
	}
	if key.SrcDev != 0 {
		t.Errorf("Expected SrcDev=0 in userspace, got %d", key.SrcDev)
	}
}

func TestMakeInnerKeyWithEmptyPath(t *testing.T) {
	key := makeInnerKey("", "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathField := strings.TrimRight(string(key.Path[:]), "\x00")
	if pathField != "" {
		t.Errorf("Expected empty Path, got %s", pathField)
	}

	sourceField := strings.TrimRight(string(key.Source[:]), "\x00")
	if sourceField != "" {
		t.Errorf("Expected empty Source, got %s", sourceField)
	}

	if key.Ino != 0 {
		t.Errorf("Expected Ino=0, got %d", key.Ino)
	}
	if key.Dev != 0 {
		t.Errorf("Expected Dev=0, got %d", key.Dev)
	}
}

func TestMakeInnerKeyPathTruncation(t *testing.T) {
	longPath := "/very/long/path/" + strings.Repeat("x", 300)

	key := makeInnerKey(longPath, "")

	if len(key.Path) != 200 {
		t.Errorf("Expected Path array to be 200 bytes, got %d", len(key.Path))
	}

	pathField := string(key.Path[:])
	if !strings.HasPrefix(pathField, "/very/long/path/") {
		t.Errorf("Expected path to start with /very/long/path/, got %s", pathField[:16])
	}
}

func TestMakeInnerKeyConsistency(t *testing.T) {
	pathStr := "/etc/passwd"

	key1 := makeInnerKey(pathStr, "")
	key2 := makeInnerKey(pathStr, "")

	if key1.KeyType != key2.KeyType {
		t.Errorf("KeyType mismatch: %d vs %d", key1.KeyType, key2.KeyType)
	}

	if key1.Path != key2.Path {
		t.Errorf("Path field mismatch")
	}

	if key1.Ino != key2.Ino || key1.Dev != key2.Dev {
		t.Errorf("Inode/device mismatch (should both be 0 in userspace)")
	}
}

func TestMakeInnerKeyWithSpecialCharacters(t *testing.T) {
	pathStr := "/etc/some-config.d/app_settings.conf"
	key := makeInnerKey(pathStr, "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathField := string(key.Path[:])
	if !strings.HasPrefix(pathField, pathStr) {
		t.Errorf("Expected path to contain special character file name")
	}
}

func TestDirtoMapBasic(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE | READ, 0}

	dirtoMap(0, "/etc/config.conf", "", m, val)

	if len(m) < 2 {
		t.Errorf("Expected at least 2 entries in map, got %d", len(m))
	}

	fullPathKey := makeInnerKey("/etc/config.conf", "")
	if _, ok := m[fullPathKey]; !ok {
		t.Errorf("Expected full path key to exist in map")
	}
}

func TestDirtoMapWithDeepPath(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE, 0}

	deepPath := "/var/lib/kubelet/pods/abc123/volumes/config"
	dirtoMap(0, deepPath, "", m, val)

	expectedPaths := []string{
		"/var/lib/kubelet/pods/abc123/volumes",  // parent directory
		"/var/lib/kubelet/pods/abc123/volumes/config", // full path
	}

	for _, path := range expectedPaths {
		key := makeInnerKey(path, "")
		if _, ok := m[key]; !ok {
			t.Errorf("Expected path key for %s to exist in map", path)
		}
	}
}

func TestDirtoMapWithSource(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE, 0}

	dirtoMap(0, "/etc/config.conf", "/home/user/source", m, val)

	if len(m) == 0 {
		t.Errorf("Expected map to have entries with source")
	}

	parentKey := makeInnerKey("/etc", "/home/user/source")
	if _, ok := m[parentKey]; !ok {
		t.Errorf("Expected parent directory key with source to exist in map")
	}
}

func TestDirtoMapBitFlags(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE | READ, EXEC}

	dirtoMap(0, "/etc/passwd", "", m, val)

	fullPathKey := makeInnerKey("/etc/passwd", "")
	if mapVal, ok := m[fullPathKey]; ok {
		if mapVal[0]&DIR == 0 {
			t.Errorf("Expected DIR flag to be set on full path entry")
		}
	} else {
		t.Errorf("Expected full path key to exist in map")
	}
}
