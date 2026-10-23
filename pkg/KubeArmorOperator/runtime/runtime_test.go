// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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

func makeSocket(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return p
}

// neverFindsRuntime is a runtimeDeps stub where no runtime is ever found.
var neverFindsRuntime = runtimeDeps{
	runtimeSockHasContainer: func(id, path string) (bool, string) { return false, "" },
	detectNRI:               DetectNRI,
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

func makeFakePod(podName, namespace, containerID string, noContainerStatus bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	}
	if !noContainerStatus {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{
			{ContainerID: containerID},
		}
	}
	return pod
}

// TestDetectRuntimeViaMapEarlyReturns covers the input-validation and early-return
// paths of DetectRuntimeViaMap that execute before any socket connection is attempted.
// The real runtimeSockHasContainer success paths (containerd/crio/docker gRPC
// handshakes against live runtime sockets) require integration tests, but
// DetectRuntimeViaMap's higher-level branching can still be unit-tested via
// detectRuntimeViaMapWithDeps using injected stubs.
func TestDetectRuntimeViaMapEarlyReturns(t *testing.T) {
	logger := zap.NewNop().Sugar()

	const (
		podName   = "test-pod"
		namespace = "default"
	)
	t.Setenv("POD_NAME", podName)
	t.Setenv("POD_NAMESPACE", namespace)

	t.Run("NoPodFound", func(t *testing.T) {
		cl := fake.NewClientset()
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA when pod not found, got %q/%q/%q", runtime, socket, nri)
		}
	})

	t.Run("EmptyContainerStatuses", func(t *testing.T) {
		cl := fake.NewClientset(makeFakePod(podName, namespace, "", true))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA with empty ContainerStatuses, got %q/%q/%q", runtime, socket, nri)
		}
	})

	t.Run("MalformedContainerID", func(t *testing.T) {
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd-abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA with malformed containerID, got %q/%q/%q", runtime, socket, nri)
		}
	})

	t.Run("RelativeExplicitSocketRejected", func(t *testing.T) {
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "relative/path.sock", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA for relative explicit socket, got %q/%q/%q", runtime, socket, nri)
		}
	})

	t.Run("NonExistentExplicitSocket", func(t *testing.T) {
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "/nonexistent/socket.sock", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA for missing socket file, got %q/%q/%q", runtime, socket, nri)
		}
	})

	t.Run("UnixPrefixStrippedBeforeAbsCheck", func(t *testing.T) {
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "unix://relative/path.sock", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA for unix:// prefixed relative path, got %q/%q/%q", runtime, socket, nri)
		}
	})

	// ExplicitSocket exists on disk but runtimeSockHasContainer returns false.
	// ContainerRuntimeSocketMap is cleared so the fallback loop also finds nothing,
	// making the test deterministic on any environment.
	t.Run("ExplicitSocketExistsButNoRuntime", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })
		common.ContainerRuntimeSocketMap = map[string][]string{}

		sockPath := makeSocket(t, t.TempDir(), "fake.sock")
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", sockPath, *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA when socket exists but no runtime, got %q/%q/%q", runtime, socket, nri)
		}
	})

	// k8sRuntime hint provided but socket file does not exist: Stat fails,
	// the warning is logged, and the fallback loop runs (also finds nothing).
	t.Run("K8sRuntimeHintSocketMissing", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })
		common.ContainerRuntimeSocketMap = map[string][]string{
			"containerd": {"/run/containerd/containerd.sock"},
		}

		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "containerd", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA when k8sRuntime socket missing, got %q/%q/%q", runtime, socket, nri)
		}
	})

	// k8sRuntime hint is empty: the k8sRuntime block is skipped entirely and the
	// fallback loop runs. With an empty socket map it finds nothing.
	t.Run("EmptyK8sRuntimeFallbackLoop", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })
		common.ContainerRuntimeSocketMap = map[string][]string{}

		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA with empty socket map, got %q/%q/%q", runtime, socket, nri)
		}
	})

	// Fallback loop: socket map has an entry whose file does not exist.
	t.Run("FallbackLoopSocketMissing", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })
		common.ContainerRuntimeSocketMap = map[string][]string{
			"docker": {"/run/docker.sock"},
		}

		cl := fake.NewClientset(makeFakePod(podName, namespace, "docker://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps("", "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA when fallback socket missing, got %q/%q/%q", runtime, socket, nri)
		}
	})

	// Fallback loop: socket file exists but runtimeSockHasContainer returns false.
	t.Run("FallbackLoopSocketExistsNoRuntime", func(t *testing.T) {
		originalMap := common.ContainerRuntimeSocketMap
		t.Cleanup(func() { common.ContainerRuntimeSocketMap = originalMap })

		dir := t.TempDir()
		relSock := "/fake.sock"
		if err := os.WriteFile(dir+relSock, []byte(""), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		common.ContainerRuntimeSocketMap = map[string][]string{
			"docker": {relSock},
		}

		cl := fake.NewClientset(makeFakePod(podName, namespace, "docker://abcdef123456", false))
		runtime, socket, nri := detectRuntimeViaMapWithDeps(dir, "", "", *logger, cl, neverFindsRuntime)
		if runtime != "NA" || socket != "NA" || nri != "NA" {
			t.Errorf("expected NA/NA/NA in fallback loop with no runtime, got %q/%q/%q", runtime, socket, nri)
		}
	})
}

// TestDockerSockHasContainer exercises dockerSockHasContainer against a dummy socket.
// client.New is lazy so New succeeds; ContainerInspect then fails, returning false.
func TestDockerSockHasContainer(t *testing.T) {
	sockPath := makeSocket(t, t.TempDir(), "docker.sock")
	if got := dockerSockHasContainer("nonexistent-id", sockPath); got {
		t.Error("expected false for dummy file, got true")
	}
}

// TestContainerdSockHasContainer exercises containerdSockHasContainer with a path
// that points to a non-containerd socket so LoadContainer fails -> false.
func TestContainerdSockHasContainer(t *testing.T) {
	sockPath := makeSocket(t, t.TempDir(), "containerd.sock")
	if got := containerdSockHasContainer("nonexistent-id", sockPath); got {
		t.Error("expected false for dummy file, got true")
	}
}

// TestDockershimSockHasContainer exercises dockershimSockHasContainer.
// grpc.NewClient is lazy (never fails at construction); ContainerStatus
// fails against the dummy socket, so the function returns false.
func TestDockershimSockHasContainer(t *testing.T) {
	sockPath := makeSocket(t, t.TempDir(), "dockershim.sock")
	if got := dockershimSockHasContainer("nonexistent-id", sockPath); got {
		t.Error("expected false for dummy file, got true")
	}
}

// TestCrioSockHasContainer exercises crioSockHasContainer the same way.
func TestCrioSockHasContainer(t *testing.T) {
	sockPath := makeSocket(t, t.TempDir(), "crio.sock")
	if got := crioSockHasContainer("nonexistent-id", sockPath); got {
		t.Error("expected false for dummy file, got true")
	}
}

// TestRuntimeSockHasContainer verifies that runtimeSockHasContainer returns
// (false, "") when all sub-checks fail against a dummy socket.
func TestRuntimeSockHasContainer(t *testing.T) {
	sockPath := makeSocket(t, t.TempDir(), "runtime.sock")
	found, rt := runtimeSockHasContainer("nonexistent-id", sockPath)
	if found {
		t.Errorf("expected found=false, got true (runtime=%q)", rt)
	}
	if rt != "" {
		t.Errorf("expected empty runtime string, got %q", rt)
	}
}

// TestContainerdNewError forces the containerd.New error branch by passing
// an empty address, which containerd rejects before any dial attempt.
func TestContainerdNewError(t *testing.T) {
	if got := containerdSockHasContainer("id", ""); got {
		t.Error("expected false on containerd.New error, got true")
	}
}

// TestDockerClientNewError forces dockerSockHasContainer to hit the client.New
// error branch by supplying a host with a null byte that the URL parser rejects.
func TestDockerClientNewError(t *testing.T) {
	if got := dockerSockHasContainer("id", "\x00invalid"); got {
		t.Error("expected false on client.New error, got true")
	}
}

// TestDetectRuntimeViaMapInjected uses detectRuntimeViaMapWithDeps to cover every
// branch that requires a runtime to actually answer. It still temporarily overrides
// common.ContainerRuntimeSocketMap for the duration of the test and restores it with
// t.Cleanup, so this test is not fully free of mutable global state.
func TestDetectRuntimeViaMapInjected(t *testing.T) {
	logger := zap.NewNop().Sugar()

	const (
		podName   = "test-pod"
		namespace = "default"
	)
	t.Setenv("POD_NAME", podName)
	t.Setenv("POD_NAMESPACE", namespace)

	origMap := common.ContainerRuntimeSocketMap
	t.Cleanup(func() { common.ContainerRuntimeSocketMap = origMap })

	// explicit socket: containerd runtime found, NRI succeeds
	t.Run("ExplicitSocket_Containerd_NRISuccess", func(t *testing.T) {
		sock := makeSocket(t, t.TempDir(), "containerd.sock")
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "containerd" },
			detectNRI:               func(prefix string) (string, error) { return "/run/nri/nri.sock", nil },
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps("", "", sock, *logger, cl, d)
		if rt != "containerd" || socket != sock || nri != "/run/nri/nri.sock" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// explicit socket: docker runtime on a path containing "containerd", NRI succeeds
	t.Run("ExplicitSocket_DockerOnContainerdPath_NRISuccess", func(t *testing.T) {
		sock := makeSocket(t, t.TempDir(), "containerd.sock")
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "docker" },
			detectNRI:               func(prefix string) (string, error) { return "/run/nri/nri.sock", nil },
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps("", "", sock, *logger, cl, d)
		if rt != "docker" || socket != sock || nri != "/run/nri/nri.sock" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// explicit socket: containerd runtime, NRI fails -> nri returned as empty string
	t.Run("ExplicitSocket_Containerd_NRIFail", func(t *testing.T) {
		sock := makeSocket(t, t.TempDir(), "containerd.sock")
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "containerd" },
			detectNRI:               func(prefix string) (string, error) { return "NA", fmt.Errorf("NRI not available") },
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps("", "", sock, *logger, cl, d)
		if rt != "containerd" || socket != sock || nri != "" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// explicit socket: non-containerd runtime (cri-o) -> no NRI check, returns directly
	t.Run("ExplicitSocket_CrioRuntime", func(t *testing.T) {
		sock := makeSocket(t, t.TempDir(), "crio.sock")
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "cri-o" },
			detectNRI:               DetectNRI,
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps("", "", sock, *logger, cl, d)
		if rt != "cri-o" || socket != sock || nri != "" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// k8sRuntime hint: socket exists, containerd found, NRI succeeds
	t.Run("K8sHint_Containerd_NRISuccess", func(t *testing.T) {
		dir := t.TempDir()
		relSock := "/containerd.sock"
		makeSocket(t, dir, "containerd.sock")
		common.ContainerRuntimeSocketMap = map[string][]string{"containerd": {relSock}}
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "containerd" },
			detectNRI:               func(prefix string) (string, error) { return "/run/nri/nri.sock", nil },
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps(dir, "containerd", "", *logger, cl, d)
		if rt != "containerd" || socket != relSock || nri != "/run/nri/nri.sock" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// k8sRuntime hint: socket exists, containerd found, NRI fails
	t.Run("K8sHint_Containerd_NRIFail", func(t *testing.T) {
		dir := t.TempDir()
		relSock := "/containerd.sock"
		makeSocket(t, dir, "containerd.sock")
		common.ContainerRuntimeSocketMap = map[string][]string{"containerd": {relSock}}
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "containerd" },
			detectNRI:               func(prefix string) (string, error) { return "NA", fmt.Errorf("NRI not available") },
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps(dir, "containerd", "", *logger, cl, d)
		if rt != "containerd" || socket != relSock || nri != "" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// k8sRuntime hint: socket exists, non-containerd runtime found
	t.Run("K8sHint_CrioRuntime", func(t *testing.T) {
		dir := t.TempDir()
		relSock := "/crio.sock"
		makeSocket(t, dir, "crio.sock")
		common.ContainerRuntimeSocketMap = map[string][]string{"cri-o": {relSock}}
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "cri-o" },
			detectNRI:               DetectNRI,
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "containerd://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps(dir, "cri-o", "", *logger, cl, d)
		if rt != "cri-o" || socket != relSock || nri != "" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})

	// fallback loop: socket exists, runtime found
	t.Run("FallbackLoop_RuntimeFound", func(t *testing.T) {
		dir := t.TempDir()
		relSock := "/docker.sock"
		makeSocket(t, dir, "docker.sock")
		common.ContainerRuntimeSocketMap = map[string][]string{"docker": {relSock}}
		d := runtimeDeps{
			runtimeSockHasContainer: func(id, path string) (bool, string) { return true, "docker" },
			detectNRI:               DetectNRI,
		}
		cl := fake.NewClientset(makeFakePod(podName, namespace, "docker://abcdef123456", false))
		rt, socket, nri := detectRuntimeViaMapWithDeps(dir, "", "", *logger, cl, d)
		if rt != "docker" || socket != relSock || nri != "" {
			t.Errorf("unexpected result: %q/%q/%q", rt, socket, nri)
		}
	})
}
