// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

type kataTestEnv struct {
	root       string
	kaRootfs   string
	outputPath string
}

func setupKataTestEnv(t *testing.T) kataTestEnv {
	t.Helper()
	root := t.TempDir()
	kaRootfs := filepath.Join(root, "ka-rootfs")
	if err := os.MkdirAll(kaRootfs, 0755); err != nil {
		t.Fatalf("failed to create kaRootfs: %v", err)
	}

	origLock := kataHookLockFile
	origBuf := kataOutputBufferFile
	origInfo := kataKubeArmorInfoFile
	origHookOut := hookOutputFile

	kataHookLockFile = filepath.Join(root, "kata.lock")
	kataOutputBufferFile = filepath.Join(root, "output.json")
	kataKubeArmorInfoFile = filepath.Join(root, "id.json")
	hookOutputFile = "/opt/kubearmor_hook_output.json"

	t.Cleanup(func() {
		kataHookLockFile = origLock
		kataOutputBufferFile = origBuf
		kataKubeArmorInfoFile = origInfo
		hookOutputFile = origHookOut
	})

	return kataTestEnv{
		root:       root,
		kaRootfs:   kaRootfs,
		outputPath: filepath.Join(kaRootfs, hookOutputFile),
	}
}

func writeBundleConfig(t *testing.T, bundleDir string, spec specs.Spec) {
	t.Helper()
	if err := os.MkdirAll(bundleDir, 0755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "config.json"), data, 0600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
}

func readContainersJSON(t *testing.T, path string) map[string]types.Container {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := make(map[string]types.Container)
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal %s (%q): %v", path, string(data), err)
	}
	return out
}

func TestRunKata_LifecycleAndEdgeCases(t *testing.T) {
	t.Run("sandbox container ignored", func(t *testing.T) {
		env := setupKataTestEnv(t)
		err := runKata(specs.State{
			ID:     "pause-1",
			Status: specs.StateCreated,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-type": "sandbox",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(kataOutputBufferFile); !os.IsNotExist(err) {
			t.Fatalf("expected buffer file not created for sandbox")
		}
		if _, err := os.Stat(env.outputPath); !os.IsNotExist(err) {
			t.Fatalf("expected rootfs output not created for sandbox")
		}
	})

	t.Run("out-of-order startup, subsequent container, and poststop", func(t *testing.T) {
		env := setupKataTestEnv(t)

		// App container starts before KubeArmor
		if err := runKata(specs.State{
			ID:     "app-1",
			Status: specs.StateCreated,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-name":    "nginx",
				"io.kubernetes.cri.sandbox-namespace": "default",
				"io.kubernetes.cri.sandbox-name":      "web-pod",
			},
		}); err != nil {
			t.Fatalf("runKata app-1 failed: %v", err)
		}

		buf := readContainersJSON(t, kataOutputBufferFile)
		c1, ok := buf["app-1"]
		if !ok {
			t.Fatalf("expected app-1 in buffer file")
		}
		if c1.PidNS == 0 || c1.MntNS == 0 {
			t.Fatalf("expected non-zero PidNS/MntNS from os.Getpid(), got pidns=%d mntns=%d", c1.PidNS, c1.MntNS)
		}
		if _, err := os.Stat(env.outputPath); !os.IsNotExist(err) {
			t.Fatalf("did not expect rootfs output file before kubearmor starts")
		}

		// KubeArmor starts with annotation + config.json Root.Path
		kaBundle := filepath.Join(env.root, "ka-bundle")
		writeBundleConfig(t, kaBundle, specs.Spec{
			Root: &specs.Root{Path: env.kaRootfs},
		})
		if err := runKata(specs.State{
			ID:     "ka-1",
			Status: specs.StateCreated,
			Bundle: kaBundle,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-name": "kubearmor",
			},
		}); err != nil {
			t.Fatalf("runKata kubearmor failed: %v", err)
		}

		infoBytes, err := os.ReadFile(kataKubeArmorInfoFile)
		if err != nil {
			t.Fatalf("expected kataKubeArmorInfoFile created: %v", err)
		}
		var info kataKubeArmorInfo
		if err := json.Unmarshal(infoBytes, &info); err != nil || info.Rootfs != env.kaRootfs {
			t.Fatalf("unexpected id.json content: %+v err=%v", info, err)
		}

		rootfsMap := readContainersJSON(t, env.outputPath)
		if _, ok := rootfsMap["app-1"]; !ok {
			t.Fatalf("expected app-1 synced into kubearmor rootfs output")
		}
		if _, ok := rootfsMap["ka-1"]; ok {
			t.Fatalf("kubearmor itself must not be in synced container map")
		}

		// Second app container starts after KubeArmor
		if err := runKata(specs.State{
			ID:     "app-2",
			Status: specs.StateCreated,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-name": "sidecar",
			},
		}); err != nil {
			t.Fatalf("runKata app-2 failed: %v", err)
		}
		buf = readContainersJSON(t, kataOutputBufferFile)
		rootfsMap = readContainersJSON(t, env.outputPath)
		if len(buf) != 2 || len(rootfsMap) != 2 {
			t.Fatalf("expected 2 containers in buffer (%d) and rootfs (%d)", len(buf), len(rootfsMap))
		}

		// Poststop app-1
		if err := runKata(specs.State{ID: "app-1", Status: specs.StateStopped}); err != nil {
			t.Fatalf("poststop app-1 failed: %v", err)
		}
		buf = readContainersJSON(t, kataOutputBufferFile)
		rootfsMap = readContainersJSON(t, env.outputPath)
		if _, has1 := buf["app-1"]; has1 || len(buf) != 1 {
			t.Fatalf("expected only app-2 in buffer after stopping app-1, got %v", buf)
		}
		if _, has1 := rootfsMap["app-1"]; has1 || len(rootfsMap) != 1 {
			t.Fatalf("expected only app-2 in rootfs after stopping app-1, got %v", rootfsMap)
		}

		// Poststop unknown ID -> no error, files unchanged
		if err := runKata(specs.State{ID: "unknown-id", Status: specs.StateStopped}); err != nil {
			t.Fatalf("poststop unknown-id failed: %v", err)
		}
		if len(readContainersJSON(t, env.outputPath)) != 1 {
			t.Fatalf("expected rootfs map unchanged after unknown poststop")
		}

		// Poststop app-2 -> valid {} written
		if err := runKata(specs.State{ID: "app-2", Status: specs.StateStopped}); err != nil {
			t.Fatalf("poststop app-2 failed: %v", err)
		}
		raw, err := os.ReadFile(env.outputPath)
		if err != nil {
			t.Fatalf("read rootfs output: %v", err)
		}
		if string(raw) != "{}" {
			t.Fatalf("expected exact {} when last container stopped, got %q", string(raw))
		}

		// Re-buffer app-3 then stop kubearmor -> removes id.json, leaves buffer untouched
		if err := runKata(specs.State{ID: "app-3", Status: specs.StateCreated, Pid: os.Getpid()}); err != nil {
			t.Fatalf("runKata app-3 failed: %v", err)
		}
		if err := runKata(specs.State{ID: "ka-1", Status: specs.StateStopped}); err != nil {
			t.Fatalf("poststop kubearmor failed: %v", err)
		}
		if _, err := os.Stat(kataKubeArmorInfoFile); !os.IsNotExist(err) {
			t.Fatalf("expected id.json removed when kubearmor stopped")
		}
		if buf := readContainersJSON(t, kataOutputBufferFile); len(buf) != 1 {
			t.Fatalf("expected app-3 preserved in buffer, got %v", buf)
		}
	})

	t.Run("kubearmor detected via config.json Args[0]", func(t *testing.T) {
		env := setupKataTestEnv(t)
		if err := runKata(specs.State{ID: "pre-app", Status: specs.StateCreated, Pid: os.Getpid()}); err != nil {
			t.Fatalf("runKata pre-app failed: %v", err)
		}

		kaBundle := filepath.Join(env.root, "ka-args-bundle")
		writeBundleConfig(t, kaBundle, specs.Spec{
			Root:    &specs.Root{Path: env.kaRootfs},
			Process: &specs.Process{Args: []string{"/KubeArmor/kubearmor", "-useOCIHooks=true"}},
		})
		if err := runKata(specs.State{
			ID:     "ka-by-args",
			Status: specs.StateCreated,
			Bundle: kaBundle,
			Pid:    os.Getpid(),
		}); err != nil {
			t.Fatalf("runKata by Args[0] failed: %v", err)
		}

		rootfsMap := readContainersJSON(t, env.outputPath)
		if _, ok := rootfsMap["pre-app"]; !ok {
			t.Fatalf("expected pre-app synced via Args[0] KubeArmor detection")
		}
		if _, ok := rootfsMap["ka-by-args"]; ok {
			t.Fatalf("ka-by-args must not be synced as monitored container")
		}
	})

	t.Run("AppArmor profile precedence and container name fallback", func(t *testing.T) {
		setupKataTestEnv(t)

		bundle := filepath.Join(t.TempDir(), "bundle")
		writeBundleConfig(t, bundle, specs.Spec{
			Process: &specs.Process{ApparmorProfile: "my-profile"},
		})

		if err := runKata(specs.State{
			ID:     "c-spec",
			Status: specs.StateCreated,
			Bundle: bundle,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-name":                   "web",
				"container.apparmor.security.beta.kubernetes.io/web": "localhost/should-not-use",
			},
		}); err != nil {
			t.Fatalf("runKata c-spec failed: %v", err)
		}

		if err := runKata(specs.State{
			ID:     "c-annot",
			Status: specs.StateCreated,
			Pid:    os.Getpid(),
			Annotations: map[string]string{
				"io.kubernetes.cri.container-name":                   "web",
				"container.apparmor.security.beta.kubernetes.io/web": "localhost/web-prof",
			},
		}); err != nil {
			t.Fatalf("runKata c-annot failed: %v", err)
		}

		if err := runKata(specs.State{
			ID:     "c-noname",
			Status: specs.StateCreated,
			Pid:    os.Getpid(),
		}); err != nil {
			t.Fatalf("runKata c-noname failed: %v", err)
		}

		buf := readContainersJSON(t, kataOutputBufferFile)
		if buf["c-spec"].AppArmorProfile != "my-profile" {
			t.Fatalf("expected my-profile from config.json, got %q", buf["c-spec"].AppArmorProfile)
		}
		if buf["c-annot"].AppArmorProfile != "web-prof" {
			t.Fatalf("expected web-prof with localhost/ stripped, got %q", buf["c-annot"].AppArmorProfile)
		}
		if buf["c-noname"].ContainerName != "c-noname" {
			t.Fatalf("expected ContainerName fallback to state.ID, got %q", buf["c-noname"].ContainerName)
		}
	})

	t.Run("concurrent runKata under race", func(t *testing.T) {
		env := setupKataTestEnv(t)

		kaBundle := filepath.Join(env.root, "ka-race-bundle")
		writeBundleConfig(t, kaBundle, specs.Spec{Root: &specs.Root{Path: env.kaRootfs}})
		if err := runKata(specs.State{
			ID:          "ka-race",
			Status:      specs.StateCreated,
			Bundle:      kaBundle,
			Pid:         os.Getpid(),
			Annotations: map[string]string{"io.kubernetes.cri.container-name": "kubearmor"},
		}); err != nil {
			t.Fatalf("kubearmor setup failed: %v", err)
		}

		const n = 10
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				id := fmt.Sprintf("conc-%d", idx)
				errs <- runKata(specs.State{
					ID:     id,
					Status: specs.StateCreated,
					Pid:    os.Getpid(),
					Annotations: map[string]string{
						"io.kubernetes.cri.container-name": fmt.Sprintf("app-%d", idx),
					},
				})
			}(i)
		}
		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent runKata error: %v", err)
			}
		}

		rootfsMap := readContainersJSON(t, env.outputPath)
		if len(rootfsMap) != n {
			t.Fatalf("expected %d containers in rootfs output, got %d", n, len(rootfsMap))
		}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("conc-%d", i)
			if _, ok := rootfsMap[id]; !ok {
				t.Fatalf("missing container %s", id)
			}
		}

		for _, dir := range []string{env.root, filepath.Dir(env.outputPath)} {
			matches, err := filepath.Glob(filepath.Join(dir, ".kubearmor-hook-*.tmp"))
			if err != nil {
				t.Fatalf("glob failed: %v", err)
			}
			if len(matches) != 0 {
				t.Fatalf("stray temp files remained in %s: %v", dir, matches)
			}
		}
	})
}

func TestResolveKataRootfs(t *testing.T) {
	bundleWithRootfs := filepath.Join(t.TempDir(), "bundle-existing")
	if err := os.MkdirAll(filepath.Join(bundleWithRootfs, "rootfs"), 0755); err != nil {
		t.Fatalf("mkdir rootfs: %v", err)
	}

	tests := []struct {
		name       string
		state      specs.State
		spec       specs.Spec
		specLoaded bool
		want       string
	}{
		{
			name:       "absolute spec.Root.Path returned as-is",
			state:      specs.State{ID: "c1", Bundle: "/some/bundle"},
			spec:       specs.Spec{Root: &specs.Root{Path: "/abs/custom/rootfs"}},
			specLoaded: true,
			want:       "/abs/custom/rootfs",
		},
		{
			name:       "relative spec.Root.Path joined with bundle",
			state:      specs.State{ID: "c1", Bundle: "/some/bundle"},
			spec:       specs.Spec{Root: &specs.Root{Path: "rootfs"}},
			specLoaded: true,
			want:       "/some/bundle/rootfs",
		},
		{
			name:       "specLoaded false with existing bundle/rootfs",
			state:      specs.State{ID: "c1", Bundle: bundleWithRootfs},
			specLoaded: false,
			want:       filepath.Join(bundleWithRootfs, "rootfs"),
		},
		{
			name:       "missing bundle falls back to kata shared path",
			state:      specs.State{ID: "c1", Bundle: ""},
			specLoaded: false,
			want:       "/var/run/kata-containers/shared/containers/c1/rootfs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveKataRootfs(tc.state, tc.spec, tc.specLoaded); got != tc.want {
				t.Fatalf("resolveKataRootfs() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteFileAtomic(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "nested", "dir", "output.json")

	first := []byte(`{"a":1}`)
	if err := writeFileAtomic(target, first, 0600); err != nil {
		t.Fatalf("first writeFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(got) != string(first) {
		t.Fatalf("content = %q, want %q", string(got), string(first))
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}

	second := []byte(`{"b":2}`)
	if err := writeFileAtomic(target, second, 0600); err != nil {
		t.Fatalf("overwrite writeFileAtomic failed: %v", err)
	}
	got, err = os.ReadFile(target)
	if err != nil {
		t.Fatalf("read after overwrite failed: %v", err)
	}
	if string(got) != string(second) {
		t.Fatalf("overwritten content = %q, want %q", string(got), string(second))
	}

	dirEntries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("readdir failed: %v", err)
	}
	for _, entry := range dirEntries {
		if strings.HasPrefix(entry.Name(), ".kubearmor-hook-") {
			t.Fatalf("stray temp file found: %s", entry.Name())
		}
	}
}
