package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTokenCacheRefresh verifies that TokenCache correctly detects changes
// to the ServiceAccount token file and returns the updated value.
func TestTokenCacheRefresh(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "token")

	// write initial token
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write first: %v", err)
	}

	// temporarily point DefaultTokenPath to our test file
	old := DefaultTokenPath
	DefaultTokenPath = path
	defer func() { DefaultTokenPath = old }()

	tc := NewTokenCache()

	// first read should return the initial token
	v, err := tc.Get()
	if err != nil {
		t.Fatalf("first get failed: %v", err)
	}
	if v != "first" {
		t.Fatalf("expected 'first', got %q", v)
	}

	// wait a little so file mtime changes reliably on all filesystems
	time.Sleep(20 * time.Millisecond)

	// write updated token (simulating rotation)
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("write second: %v", err)
	}

	// Get() should detect the mtime change and return the new token
	v2, err := tc.Get()
	if err != nil {
		t.Fatalf("second get failed: %v", err)
	}
	if v2 != "second" {
		t.Fatalf("expected 'second', got %q", v2)
	}
}
