// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestMakeInnerKeyWithPath(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	key := makeInnerKey(tmpfile.Name(), "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathStr := string(key.Path[:])
	if !strings.HasPrefix(pathStr, tmpfile.Name()) {
		t.Errorf("Expected path to contain %s, got %s", tmpfile.Name(), pathStr[:len(tmpfile.Name())])
	}

	stat, _ := os.Stat(tmpfile.Name())
	sysstat := stat.Sys().(*syscall.Stat_t)

	if key.Ino != sysstat.Ino {
		t.Errorf("Expected Ino=%d, got %d", sysstat.Ino, key.Ino)
	}

	if key.Dev != sysstat.Dev {
		t.Errorf("Expected Dev=%d, got %d", sysstat.Dev, key.Dev)
	}

	if key.SrcIno != 0 {
		t.Errorf("Expected SrcIno=0, got %d", key.SrcIno)
	}

	if key.SrcDev != 0 {
		t.Errorf("Expected SrcDev=0, got %d", key.SrcDev)
	}
}

func TestMakeInnerKeyWithPathAndSource(t *testing.T) {
	tmpfile1, err := os.CreateTemp("", "test1")
	if err != nil {
		t.Fatalf("Failed to create temp file 1: %v", err)
	}
	defer os.Remove(tmpfile1.Name())
	tmpfile1.Close()

	tmpfile2, err := os.CreateTemp("", "test2")
	if err != nil {
		t.Fatalf("Failed to create temp file 2: %v", err)
	}
	defer os.Remove(tmpfile2.Name())
	tmpfile2.Close()

	key := makeInnerKey(tmpfile1.Name(), tmpfile2.Name())

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathStr := string(key.Path[:])
	if !strings.HasPrefix(pathStr, tmpfile1.Name()) {
		t.Errorf("Expected path to contain %s, got %s", tmpfile1.Name(), pathStr[:len(tmpfile1.Name())])
	}

	sourceStr := string(key.Source[:])
	if !strings.HasPrefix(sourceStr, tmpfile2.Name()) {
		t.Errorf("Expected source to contain %s, got %s", tmpfile2.Name(), sourceStr[:len(tmpfile2.Name())])
	}

	stat1, _ := os.Stat(tmpfile1.Name())
	sysstat1 := stat1.Sys().(*syscall.Stat_t)

	if key.Ino != sysstat1.Ino {
		t.Errorf("Expected Ino=%d, got %d", sysstat1.Ino, key.Ino)
	}

	if key.Dev != sysstat1.Dev {
		t.Errorf("Expected Dev=%d, got %d", sysstat1.Dev, key.Dev)
	}

	stat2, _ := os.Stat(tmpfile2.Name())
	sysstat2 := stat2.Sys().(*syscall.Stat_t)

	if key.SrcIno != sysstat2.Ino {
		t.Errorf("Expected SrcIno=%d, got %d", sysstat2.Ino, key.SrcIno)
	}

	if key.SrcDev != sysstat2.Dev {
		t.Errorf("Expected SrcDev=%d, got %d", sysstat2.Dev, key.SrcDev)
	}
}

func TestMakeInnerKeyWithEmptyPath(t *testing.T) {
	key := makeInnerKey("", "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	if key.Ino != 0 {
		t.Errorf("Expected Ino=0, got %d", key.Ino)
	}

	if key.Dev != 0 {
		t.Errorf("Expected Dev=0, got %d", key.Dev)
	}

	if key.SrcIno != 0 {
		t.Errorf("Expected SrcIno=0, got %d", key.SrcIno)
	}

	if key.SrcDev != 0 {
		t.Errorf("Expected SrcDev=0, got %d", key.SrcDev)
	}
}

func TestMakeInnerKeyWithNonExistentPath(t *testing.T) {
	nonExistentPath := "/tmp/this/path/does/not/exist/hopefully"

	key := makeInnerKey(nonExistentPath, "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	pathStr := string(key.Path[:])
	if !strings.Contains(pathStr, "path/does/not/exist") {
		t.Errorf("Expected path to contain path parts, got %s", pathStr)
	}

	if key.Ino != 0 {
		t.Errorf("Expected Ino=0 for non-existent path, got %d", key.Ino)
	}

	if key.Dev != 0 {
		t.Errorf("Expected Dev=0 for non-existent path, got %d", key.Dev)
	}
}

func TestMakeInnerKeyWithSymlink(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-original")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	tmpdir := filepath.Dir(tmpfile.Name())
	symlinkPath := filepath.Join(tmpdir, "test-symlink")
	if err := os.Symlink(tmpfile.Name(), symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}
	defer os.Remove(symlinkPath)

	keySymlink := makeInnerKey(symlinkPath, "")
	keyOriginal := makeInnerKey(tmpfile.Name(), "")

	if keySymlink.Ino != keyOriginal.Ino {
		t.Errorf("Symlink and original should have same Ino. Symlink=%d, Original=%d",
			keySymlink.Ino, keyOriginal.Ino)
	}

	if keySymlink.Dev != keyOriginal.Dev {
		t.Errorf("Symlink and original should have same Dev. Symlink=%d, Original=%d",
			keySymlink.Dev, keyOriginal.Dev)
	}

	pathSymlink := string(keySymlink.Path[:])
	pathOriginal := string(keyOriginal.Path[:])

	if strings.TrimRight(pathSymlink, "\x00") == strings.TrimRight(pathOriginal, "\x00") {
		t.Errorf("Symlink path and original path should be different")
	}
}

func TestDirtoMap(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE | READ, 0}

	dirtoMap(0, "/etc/config.conf", "", m, val)

	parentKey := makeInnerKey("/etc", "")
	if _, ok := m[parentKey]; !ok {
		t.Errorf("Expected parent directory key to exist in map")
	}

	fullPathKey := makeInnerKey("/etc/config.conf", "")
	if _, ok := m[fullPathKey]; !ok {
		t.Errorf("Expected full path key to exist in map")
	}

	hintKey := makeInnerKey("/", "")
	if _, ok := m[hintKey]; !ok {
		t.Errorf("Expected hint key for / to exist in map")
	}
}

func TestDirtoMapWithDeepPath(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE, 0}

	deepPath := "/var/lib/kubelet/pods/abc123/volumes/config"
	dirtoMap(0, deepPath, "", m, val)

	expectedDirs := []string{
		"/var/lib/kubelet/pods/abc123/volumes",
		"/var/lib/kubelet/pods/abc123/volumes/config",
		"/",
		"/var/",
		"/var/lib/",
		"/var/lib/kubelet/",
		"/var/lib/kubelet/pods/",
		"/var/lib/kubelet/pods/abc123/",
	}

	for _, dir := range expectedDirs {
		key := makeInnerKey(dir, "")
		if _, ok := m[key]; !ok {
			t.Errorf("Expected directory key for %s to exist in map", dir)
		}
	}
}

func TestDirtoMapWithSource(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE, 0}

	dirtoMap(0, "/etc/config.conf", "/home/user/source", m, val)

	parentKey := makeInnerKey("/etc", "/home/user/source")

	if _, ok := m[parentKey]; !ok {
		t.Errorf("Expected parent directory key with source to exist in map")
	}

	sourceStr := string(parentKey.Source[:])
	if !strings.Contains(sourceStr, "source") {
		t.Errorf("Expected source path to be in key")
	}
}

func TestDirtoMapBitFlags(t *testing.T) {
	m := make(map[InnerKey][2]uint16)
	val := [2]uint16{WRITE | READ, EXEC}

	dirtoMap(0, "/etc/passwd", "", m, val)

	fullPathKey := makeInnerKey("/etc/passwd", "")
	if mapVal, ok := m[fullPathKey]; ok {
		if mapVal[0]&DIR == 0 {
			t.Errorf("Expected DIR flag to be set on full path")
		}
	}
}

func TestMakeInnerKeyPathTruncation(t *testing.T) {
	tmpdir := os.TempDir()

	longPath := filepath.Join(tmpdir, strings.Repeat("very_long_directory_name_", 5))
	os.MkdirAll(longPath, 0755)
	defer os.RemoveAll(tmpdir + "/very_long_directory_name_")

	key := makeInnerKey(longPath, "")

	if len(key.Path) != 200 {
		t.Errorf("Expected Path array to be 200 bytes, got %d", len(key.Path))
	}

	pathStr := string(key.Path[:])
	if !strings.HasPrefix(pathStr, tmpdir) {
		t.Errorf("Expected path to start with tmpdir %s", tmpdir)
	}
}

func TestMakeInnerKeyConsistency(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-consistency")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	key1 := makeInnerKey(tmpfile.Name(), "")
	key2 := makeInnerKey(tmpfile.Name(), "")

	if key1.Ino != key2.Ino {
		t.Errorf("Same path should always have same Ino. Got %d vs %d", key1.Ino, key2.Ino)
	}

	if key1.Dev != key2.Dev {
		t.Errorf("Same path should always have same Dev. Got %d vs %d", key1.Dev, key2.Dev)
	}

	if key1.Path != key2.Path {
		t.Errorf("Same path should always have identical Path field")
	}
}

func TestMakeInnerKeyWithSpecialCharacters(t *testing.T) {
	tmpdir := os.TempDir()
	specialPath := filepath.Join(tmpdir, "test-dir_with-special.chars")

	os.MkdirAll(specialPath, 0755)
	defer os.RemoveAll(specialPath)

	key := makeInnerKey(specialPath, "")

	if key.KeyType != 1 {
		t.Errorf("Expected KeyType=1, got %d", key.KeyType)
	}

	if key.Ino == 0 {
		t.Errorf("Expected valid Ino for existing directory")
	}

	pathStr := string(key.Path[:])
	if !strings.Contains(pathStr, "test-dir_with-special.chars") {
		t.Errorf("Expected path to contain special character file name")
	}
}
