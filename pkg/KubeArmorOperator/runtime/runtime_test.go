// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
)

func TestDetectRuntimeViaMapWithExplicitSocket(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// Test case 1: Valid explicit socket
	t.Run("ValidExplicitSocket", func(t *testing.T) {
		pathPrefix := t.TempDir()
		socketPath := "/var/run/containerd/containerd.sock"
		fullPath := filepath.Clean(pathPrefix + socketPath)

		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("Failed to create directories: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(""), 0o644); err != nil {
			t.Fatalf("Failed to create socket file: %v", err)
		}

		runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "", socketPath, *logger)

		if runtime != "containerd" {
			t.Errorf("Expected runtime 'containerd', got '%s'", runtime)
		}

		if socket != socketPath {
			t.Errorf("Expected socket '%s', got '%s'", socketPath, socket)
		}
	})

	// Test case 2: Non-existent explicit socket
	t.Run("NonExistentExplicitSocket", func(t *testing.T) {
		runtime, socket, _ := DetectRuntimeViaMap("", "", "/nonexistent/socket.sock", *logger)

		if runtime != "NA" {
			t.Errorf("Expected runtime 'NA', got '%s'", runtime)
		}

		if socket != "NA" {
			t.Errorf("Expected socket 'NA', got '%s'", socket)
		}
	})

	// Test case 3: Relative explicit socket should be rejected
	t.Run("RelativeExplicitSocket", func(t *testing.T) {
		runtime, socket, _ := DetectRuntimeViaMap("", "", "containerd/containerd.sock", *logger)

		if runtime != "NA" {
			t.Errorf("Expected runtime 'NA' for relative path, got '%s'", runtime)
		}

		if socket != "NA" {
			t.Errorf("Expected socket 'NA' for relative path, got '%s'", socket)
		}
	})
}

func TestDetermineRuntimeFromSocket(t *testing.T) {
	testCases := []struct {
		socketPath      string
		expectedRuntime string
	}{
		{"/var/run/docker.sock", "docker"},
		{"/run/containerd/containerd.sock", "containerd"},
		{"/var/run/crio/crio.sock", "cri-o"},
		{"/run/k3s/containerd/containerd.sock", "containerd"},
		{"/some/unknown/path.sock", "containerd"}, // fallback
	}

	for _, tc := range testCases {
		t.Run(tc.socketPath, func(t *testing.T) {
			result := determineRuntimeFromSocket(tc.socketPath)
			if result != tc.expectedRuntime {
				t.Errorf("For socket %s, expected runtime %s, got %s",
					tc.socketPath, tc.expectedRuntime, result)
			}
		})
	}
}

func TestDetectRuntimeViaMapAutoDetection(t *testing.T) {
	logger := zap.NewNop().Sugar()

	originalMap := common.ContainerRuntimeSocketMap
	t.Cleanup(func() {
		common.ContainerRuntimeSocketMap = originalMap
	})

	socketPath := "/var/run/containerd/containerd.sock"
	common.ContainerRuntimeSocketMap = map[string][]string{
		"containerd": {socketPath},
	}

	pathPrefix := t.TempDir()
	fullPath := filepath.Clean(pathPrefix + socketPath)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("Failed to create directories: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(""), 0o644); err != nil {
		t.Fatalf("Failed to write socket file: %v", err)
	}

	runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "containerd", "", *logger)

	if runtime != "containerd" {
		t.Fatalf("Expected runtime 'containerd', got '%s'", runtime)
	}

	if socket != socketPath {
		t.Fatalf("Expected socket '%s', got '%s'", socketPath, socket)
	}
}
