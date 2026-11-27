// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Default log rotation parameters
const (
	DefaultLogMaxSizeMB  = 10
	DefaultLogMaxBackups = 5
)

// LogRotator provides thread-safe size-based file rotation with backup archiving and pruning.
type LogRotator struct {
	sync.Mutex
	filePath     string
	maxSizeBytes int64
	maxBackups   int
	file         *os.File
	currentSize  int64
}

// NewLogRotator creates a new LogRotator instance for the given file path.
// maxSizeMB: maximum file size in megabytes before rotation (default: 10).
// maxBackups: maximum number of rotated backup archives to keep (default: 5).
func NewLogRotator(filePath string, maxSizeMB int, maxBackups int) (*LogRotator, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = DefaultLogMaxSizeMB
	}
	if maxBackups <= 0 {
		maxBackups = DefaultLogMaxBackups
	}

	cleanPath := filepath.Clean(filePath)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", cleanPath, err)
	}

	var size int64
	if stat, err := f.Stat(); err == nil {
		size = stat.Size()
	}

	return &LogRotator{
		filePath:     cleanPath,
		maxSizeBytes: int64(maxSizeMB) * 1024 * 1024,
		maxBackups:   maxBackups,
		file:         f,
		currentSize:  size,
	}, nil
}

// WriteString writes a string to the log file, automatically rotating if size limit is exceeded.
func (r *LogRotator) WriteString(s string) error {
	r.Lock()
	defer r.Unlock()

	data := []byte(s)
	dataLen := int64(len(data))

	if r.currentSize+dataLen >= r.maxSizeBytes && r.currentSize > 0 {
		if err := r.rotate(); err != nil {
			return err
		}
	}

	n, err := r.file.Write(data)
	r.currentSize += int64(n)
	return err
}

// Write implements io.Writer, writing bytes to the log file and rotating when size limit is reached.
func (r *LogRotator) Write(p []byte) (int, error) {
	r.Lock()
	defer r.Unlock()

	dataLen := int64(len(p))
	if r.currentSize+dataLen >= r.maxSizeBytes && r.currentSize > 0 {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := r.file.Write(p)
	r.currentSize += int64(n)
	return n, err
}

// rotate closes the current file, shifts backup archives, and opens a fresh log file.
// Must be called with r.Lock held.
func (r *LogRotator) rotate() error {
	if r.file != nil {
		_ = r.file.Sync()
		_ = r.file.Close()
		r.file = nil
	}

	// Remove oldest backup exceeding maxBackups
	if r.maxBackups > 0 {
		oldest := fmt.Sprintf("%s.%d", r.filePath, r.maxBackups)
		_ = os.Remove(oldest)

		// Shift existing archives downwards: .1 -> .2, .2 -> .3, etc.
		for i := r.maxBackups - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", r.filePath, i)
			dst := fmt.Sprintf("%s.%d", r.filePath, i+1)
			if _, err := os.Stat(src); err == nil {
				_ = os.Rename(src, dst)
			}
		}

		// Move current active log to .1
		dst1 := fmt.Sprintf("%s.1", r.filePath)
		_ = os.Rename(r.filePath, dst1)
	} else {
		// maxBackups == 0 means truncate without retaining archives
		_ = os.Remove(r.filePath)
	}

	// Open a fresh file
	f, err := os.OpenFile(r.filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to recreate log file %s after rotation: %w", r.filePath, err)
	}

	r.file = f
	r.currentSize = 0
	return nil
}

// File returns the active os.File handle.
func (r *LogRotator) File() *os.File {
	r.Lock()
	defer r.Unlock()
	return r.file
}

// CurrentSize returns the current uncompressed byte size of the active log file.
func (r *LogRotator) CurrentSize() int64 {
	r.Lock()
	defer r.Unlock()
	return r.currentSize
}

// Close flushes and closes the active log file.
func (r *LogRotator) Close() error {
	r.Lock()
	defer r.Unlock()

	if r.file != nil {
		_ = r.file.Sync()
		err := r.file.Close()
		r.file = nil
		return err
	}
	return nil
}
