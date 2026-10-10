// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLogRotatorBasic(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "kubearmor.log")

	rotator, err := NewLogRotator(logPath, 1, 3)
	if err != nil {
		t.Fatalf("Failed to create LogRotator: %v", err)
	}
	defer rotator.Close()

	if rotator.File() == nil {
		t.Fatal("Expected active file handle to be non-nil")
	}

	testMsg := "test log entry\n"
	if err := rotator.WriteString(testMsg); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}

	if rotator.CurrentSize() != int64(len(testMsg)) {
		t.Fatalf("Expected size %d, got %d", len(testMsg), rotator.CurrentSize())
	}
}

func TestLogRotatorRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	rotator, err := NewLogRotator(logPath, 1, 2)
	if err != nil {
		t.Fatalf("Failed to create LogRotator: %v", err)
	}
	defer rotator.Close()

	// Artificially set maxSizeBytes to a small threshold for testing rotation
	rotator.maxSizeBytes = 100

	chunk := "12345678901234567890\n" // 21 bytes

	// Write enough chunks to trigger rotation multiple times
	for i := 0; i < 20; i++ {
		if err := rotator.WriteString(chunk); err != nil {
			t.Fatalf("WriteString failed at iteration %d: %v", i, err)
		}
	}

	// Verify primary log and archives exist
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatalf("Expected primary log file %s to exist", logPath)
	}

	archive1 := fmt.Sprintf("%s.1", logPath)
	if _, err := os.Stat(archive1); os.IsNotExist(err) {
		t.Fatalf("Expected backup archive %s to exist", archive1)
	}

	archive2 := fmt.Sprintf("%s.2", logPath)
	if _, err := os.Stat(archive2); os.IsNotExist(err) {
		t.Fatalf("Expected backup archive %s to exist", archive2)
	}

	// Archive 3 should not exist since maxBackups is 2
	archive3 := fmt.Sprintf("%s.3", logPath)
	if _, err := os.Stat(archive3); err == nil {
		t.Fatalf("Archive %s should have been pruned (maxBackups=2)", archive3)
	}
}

func TestLogRotatorConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "concurrent.log")

	rotator, err := NewLogRotator(logPath, 1, 3)
	if err != nil {
		t.Fatalf("Failed to create LogRotator: %v", err)
	}
	defer rotator.Close()

	// Small threshold to force rotations during concurrent writes
	rotator.maxSizeBytes = 256

	var wg sync.WaitGroup
	workers := 10
	iterations := 25

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				msg := fmt.Sprintf("worker-%d entry-%d\n", workerID, i)
				_ = rotator.WriteString(msg)
			}
		}(w)
	}

	wg.Wait()

	// Check that log file is valid and readable
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Expected log file to have content")
	}
}
