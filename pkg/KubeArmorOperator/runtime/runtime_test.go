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

func createSocket(t *testing.T, pathPrefix, relPath string) {
	t.Helper()
	full := filepath.Clean(pathPrefix + relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func createNRI(t *testing.T, pathPrefix string) {
	t.Helper()
	for _, p := range common.ContainerRuntimeSocketMap["nri"] {
		createSocket(t, pathPrefix, p)
		return // one is enough
	}
}

func TestDetectNRI(t *testing.T) {
	originalMap := common.ContainerRuntimeSocketMap
	t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

	nriPath := "/run/nri/nri.sock"
	common.ContainerRuntimeSocketMap = map[string][]string{
		"nri": {nriPath},
	}

	t.Run("NRISocketExists", func(t *testing.T) {
		pathPrefix := t.TempDir()
		createSocket(t, pathPrefix, nriPath)

		got, err := DetectNRI(pathPrefix)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if got != nriPath {
			t.Errorf("expected %q, got %q", nriPath, got)
		}
	})

	t.Run("NRISocketMissing", func(t *testing.T) {
		got, err := DetectNRI(t.TempDir())
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if got != "NA" {
			t.Errorf("expected \"NA\", got %q", got)
		}
	})
}

func TestDetectRuntimeViaMapWithExplicitSocket(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("ValidExplicitSocket", func(t *testing.T) {
		pathPrefix := t.TempDir()
		socketPath := "/var/run/containerd/containerd.sock"
		createSocket(t, pathPrefix, socketPath)

		runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "", socketPath, *logger)
		if runtime != "containerd" {
			t.Errorf("expected 'containerd', got %q", runtime)
		}
		if socket != socketPath {
			t.Errorf("expected %q, got %q", socketPath, socket)
		}
	})

	t.Run("NonExistentExplicitSocket", func(t *testing.T) {
		runtime, socket, _ := DetectRuntimeViaMap("", "", "/nonexistent/socket.sock", *logger)
		if runtime != "NA" {
			t.Errorf("expected 'NA', got %q", runtime)
		}
		if socket != "NA" {
			t.Errorf("expected 'NA', got %q", socket)
		}
	})

	t.Run("RelativeExplicitSocket", func(t *testing.T) {
		runtime, socket, _ := DetectRuntimeViaMap("", "", "containerd/containerd.sock", *logger)
		if runtime != "NA" {
			t.Errorf("expected 'NA' for relative path, got %q", runtime)
		}
		if socket != "NA" {
			t.Errorf("expected 'NA' for relative path, got %q", socket)
		}
	})

	t.Run("ExplicitSocketWithUnixPrefix", func(t *testing.T) {
		pathPrefix := t.TempDir()
		hostPath := "/var/run/docker.sock"
		createSocket(t, pathPrefix, hostPath)

		runtime, socket, nri := DetectRuntimeViaMap(pathPrefix, "", "unix://"+hostPath, *logger)
		if runtime != "docker" {
			t.Errorf("expected 'docker', got %q", runtime)
		}
		if socket != hostPath {
			t.Errorf("expected %q, got %q", hostPath, socket)
		}
		if nri != "" {
			t.Errorf("expected empty NRI for docker socket, got %q", nri)
		}
	})

	t.Run("ExplicitContainerdSocketWithNRI", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		nriSock := "/run/nri/nri.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"nri": {nriSock},
		}

		pathPrefix := t.TempDir()
		socketPath := "/var/run/containerd/containerd.sock"
		createSocket(t, pathPrefix, socketPath)
		createSocket(t, pathPrefix, nriSock)

		runtime, socket, nri := DetectRuntimeViaMap(pathPrefix, "", socketPath, *logger)
		if runtime != "containerd" {
			t.Errorf("expected 'containerd', got %q", runtime)
		}
		if socket != socketPath {
			t.Errorf("expected %q, got %q", socketPath, socket)
		}
		if nri != nriSock {
			t.Errorf("expected NRI path %q, got %q", nriSock, nri)
		}
	})

	t.Run("DockerSocketContainingContainerd", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		nriSock := "/run/nri/nri.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"nri": {nriSock},
		}

		pathPrefix := t.TempDir()
		socketPath := "/var/run/docker/containerd/docker.sock"
		createSocket(t, pathPrefix, socketPath)
		createSocket(t, pathPrefix, nriSock)

		runtime, socket, nri := DetectRuntimeViaMap(pathPrefix, "", socketPath, *logger)
		if runtime != "docker" {
			t.Errorf("expected 'docker', got %q", runtime)
		}
		if socket != socketPath {
			t.Errorf("expected %q, got %q", socketPath, socket)
		}
		if nri != nriSock {
			t.Errorf("expected NRI path %q, got %q", nriSock, nri)
		}
	})
}

func TestDetectRuntimeViaMapAutoDetection(t *testing.T) {
	logger := zap.NewNop().Sugar()

	t.Run("K8sRuntimeHintMatches", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		socketPath := "/var/run/containerd/containerd.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"containerd": {socketPath},
		}

		pathPrefix := t.TempDir()
		createSocket(t, pathPrefix, socketPath)

		runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "containerd", "", *logger)
		if runtime != "containerd" {
			t.Fatalf("expected 'containerd', got %q", runtime)
		}
		if socket != socketPath {
			t.Fatalf("expected %q, got %q", socketPath, socket)
		}
	})

	t.Run("K8sRuntimeContainerdWithNRI", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		socketPath := "/var/run/containerd/containerd.sock"
		nriSock := "/run/nri/nri.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"containerd": {socketPath},
			"nri":        {nriSock},
		}

		pathPrefix := t.TempDir()
		createSocket(t, pathPrefix, socketPath)
		createSocket(t, pathPrefix, nriSock)

		runtime, socket, nri := DetectRuntimeViaMap(pathPrefix, "containerd", "", *logger)
		if runtime != "containerd" {
			t.Errorf("expected 'containerd', got %q", runtime)
		}
		if socket != socketPath {
			t.Errorf("expected %q, got %q", socketPath, socket)
		}
		if nri != nriSock {
			t.Errorf("expected NRI path %q, got %q", nriSock, nri)
		}
	})

	t.Run("K8sRuntimeHintMissesButFallbackFinds", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		hintedSocket := "/var/run/containerd/containerd.sock"
		fallbackSocket := "/var/run/crio/crio.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"containerd": {hintedSocket},
			"cri-o":      {fallbackSocket},
		}

		pathPrefix := t.TempDir()
		createSocket(t, pathPrefix, fallbackSocket)

		runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "containerd", "", *logger)
		if runtime == "NA" {
			t.Errorf("expected a runtime to be detected via fallback scan, got 'NA'")
		}
		if socket == "NA" {
			t.Errorf("expected a socket to be detected via fallback scan, got 'NA'")
		}
	})

	t.Run("NoRuntimeDetected", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		common.ContainerRuntimeSocketMap = map[string][]string{
			"containerd": {"/var/run/containerd/containerd.sock"},
		}

		pathPrefix := t.TempDir()

		runtime, socket, nri := DetectRuntimeViaMap(pathPrefix, "", "", *logger)
		if runtime != "NA" {
			t.Errorf("expected 'NA', got %q", runtime)
		}
		if socket != "NA" {
			t.Errorf("expected 'NA', got %q", socket)
		}
		if nri != "NA" {
			t.Errorf("expected 'NA', got %q", nri)
		}
	})

	t.Run("K8sRuntimeCRIO", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		socketPath := "/var/run/crio/crio.sock"
		common.ContainerRuntimeSocketMap = map[string][]string{
			"cri-o": {socketPath},
		}

		pathPrefix := t.TempDir()
		createSocket(t, pathPrefix, socketPath)

		runtime, socket, _ := DetectRuntimeViaMap(pathPrefix, "cri-o", "", *logger)
		if runtime != "cri-o" {
			t.Errorf("expected 'cri-o', got %q", runtime)
		}
		if socket != socketPath {
			t.Errorf("expected %q, got %q", socketPath, socket)
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
		{"/var/run/cri-o/cri-o.sock", "cri-o"},
		{"/run/k3s/containerd/containerd.sock", "containerd"},
		{"/some/unknown/path.sock", "containerd"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.socketPath, func(t *testing.T) {
			result := determineRuntimeFromSocket(tc.socketPath)
			if result != tc.expectedRuntime {
				t.Errorf("socket %q: expected %q, got %q",
					tc.socketPath, tc.expectedRuntime, result)
			}
		})
	}
}
