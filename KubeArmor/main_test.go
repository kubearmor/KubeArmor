// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var clusterPtr, gRPCPtr, logPathPtr *string
var enableKubeArmorPolicyPtr, enableKubeArmorHostPolicyPtr, enableKubeArmorVMPtr, coverageTestPtr, enableK8sEnv, tlsEnabled *bool
var defaultFilePosturePtr, defaultCapabilitiesPosturePtr, defaultNetworkPosturePtr, hostDefaultCapabilitiesPosturePtr, hostDefaultNetworkPosturePtr, hostDefaultFilePosturePtr, procFsMountPtr, lsmOrder *string

// libraryFlags holds the flags that imported packages registered on the default
// FlagSet (e.g. controller-runtime's -kubeconfig). They are not KubeArmor flags
// and must not be forwarded to main(), whose fresh FlagSet does not define them.
var libraryFlags = map[string]bool{}

func init() {
	flag.VisitAll(func(f *flag.Flag) { libraryFlags[f.Name] = true })

	// options (string)
	clusterPtr = flag.String("cluster", "default", "cluster name")

	// options (string)
	gRPCPtr = flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr = flag.String("logPath", "none", "log file path")

	// options (string)
	defaultFilePosturePtr = flag.String("defaultFilePosture", "block", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosturePtr = flag.String("defaultNetworkPosture", "block", "configuring default enforcement action in global network context {allow|audit|block}")
	defaultCapabilitiesPosturePtr = flag.String("defaultCapabilitiesPosture", "block", "configuring default enforcement action in global capability context {allow|audit|block}")

	hostDefaultFilePosturePtr = flag.String("hostDefaultFilePosture", "block", "configuring default enforcement action in global file context {allow|audit|block}")
	hostDefaultNetworkPosturePtr = flag.String("hostDefaultNetworkPosture", "block", "configuring default enforcement action in global network context {allow|audit|block}")
	hostDefaultCapabilitiesPosturePtr = flag.String("hostDefaultCapabilitiesPosture", "block", "configuring default enforcement action in global capability context {allow|audit|block}")

	procFsMountPtr = flag.String("procfsMount", "/proc", "Path to the BPF filesystem to use for storing maps")

	// options (boolean)
	enableKubeArmorPolicyPtr = flag.Bool("enableKubeArmorPolicy", true, "enabling KubeArmorPolicy")
	enableKubeArmorHostPolicyPtr = flag.Bool("enableKubeArmorHostPolicy", true, "enabling KubeArmorHostPolicy")
	enableKubeArmorVMPtr = flag.Bool("enableKubeArmorVm", false, "enabling KubeArmorVM")

	enableK8sEnv = flag.Bool("k8s", true, "is k8s env?")
	tlsEnabled = flag.Bool("tlsEnabled", false, "enable tls for secure connection?")

	// options (boolean)
	coverageTestPtr = flag.Bool("coverageTest", false, "enabling CoverageTest")
	lsmOrder = flag.String("lsm", "bpf,apparmor,selinux", "LSM order to be set in the system")

	registerPassthroughFlags(os.Args[1:])
}

// registerPassthroughFlags declares every flag in args that this test binary
// does not already know about (e.g. -criSocket, -nriSocket, --useOCIHooks).
// The go test binary parses os.Args itself and exits on undefined flags, and
// TestMain only forwards flags that are registered, so without this the flags
// the operator passes to the coverage image are rejected or silently dropped.
// Flags of the form -name=value are kept as strings, bare -name as booleans.
func registerPassthroughFlags(args []string) {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
			// flag parsing stops at the first non-flag argument or terminator
			return
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name == "" || strings.HasPrefix(name, "test.") || flag.Lookup(name) != nil {
			continue
		}
		if hasValue {
			flag.String(name, "", "passed through to KubeArmor")
		} else {
			flag.Bool(name, false, "passed through to KubeArmor")
		}
	}
}

// forwardedArgs returns the command line handed to main(): every flag registered
// by this file, i.e. the ones declared in init with the coverage defaults plus
// any extra flags passed on the command line. prog is Args[0], which
// flag.Parse skips.
func forwardedArgs(prog string) []string {
	args := []string{prog}
	flag.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "test.") || libraryFlags[f.Name] {
			return
		}
		args = append(args, fmt.Sprintf("-%s=%s", f.Name, f.Value.String()))
	})
	return args
}

// TestMain - test to drive external testing coverage
func TestMain(t *testing.T) {
	args := forwardedArgs(os.Args[0])

	// Reset Test Flags before executing main
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	os.Args = args

	t.Log("[INFO] Executed KubeArmor")
	main()
	t.Log("[INFO] Terminated KubeArmor")
}

func TestBpfMapFiltering(t *testing.T) {
	cases := []struct {
		filename string
		want     bool
	}{
		{"kubearmor_events", true},
		{"kubearmor_policy", true},
		{"cilium_events", false},
		{"kube", false},
		{"", false},
		{"KubeArmor", false},
	}
	for _, tc := range cases {
		got := isKubeArmorBpfMap(tc.filename)
		if got != tc.want {
			t.Errorf("isKubeArmorBpfMap(%q) = %v, want %v", tc.filename, got, tc.want)
		}
	}
}

func TestBpfDirCleanupWithTempDir(t *testing.T) {
	dir := t.TempDir()
	files := map[string]bool{
		"kubearmor_events": true,
		"kubearmor_policy": true,
		"cilium_events":    false,
	}
	for name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatalf("failed to create fixture file %q: %v", name, err)
		}
	}
	err := cleanupBpfMaps(dir, os.Remove)
	if err != nil {
		t.Fatalf("cleanupBpfMaps returned unexpected error: %v", err)
	}
	for name, shouldDelete := range files {
		_, err := os.Stat(filepath.Join(dir, name))
		if shouldDelete && err == nil {
			t.Errorf("%s should have been deleted", name)
		}
		if !shouldDelete && err != nil {
			t.Errorf("%s should still exist", name)
		}
	}
}

func TestBpfDirCleanupSkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "kubearmor_subdir")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	err := cleanupBpfMaps(dir, os.Remove)
	if err != nil {
		t.Fatalf("cleanupBpfMaps returned unexpected error: %v", err)
	}
	if _, err := os.Stat(sub); os.IsNotExist(err) {
		t.Error("subdir was incorrectly removed")
	}
}

func TestBpfDirCleanupMissingDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("failed to remove temp dir: %v", err)
	}
	err := cleanupBpfMaps(dir, os.Remove)
	if err == nil {
		t.Error("expected error for missing dir")
	}
}

func TestNonRootWithoutUBI(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must run as non-root")
	}
	t.Setenv("KUBEARMOR_UBI", "")
	main()
}

// func TestPassthroughFlags(t *testing.T) {
// 	registerPassthroughFlags([]string{
// 		"-test.coverprofile=/coverage/c.out",
// 		"-ptCriSocket=unix:///run/containerd/containerd.sock",
// 		"--ptUseOCIHooks",
// 		"-lsm=bpf",
// 		"--",
// 		"-ptAfterTerminator=x",
// 	})

// 	// the go test flag parsing would have set these from the command line
// 	for name, value := range map[string]string{
// 		"ptCriSocket":   "unix:///run/containerd/containerd.sock",
// 		"ptUseOCIHooks": "true",
// 	} {
// 		if err := flag.Set(name, value); err != nil {
// 			t.Fatalf("flag %q was not registered: %v", name, err)
// 		}
// 	}
// 	if flag.Lookup("ptAfterTerminator") != nil {
// 		t.Error("flag after -- must not be registered")
// 	}
// 	if flag.Lookup("test.coverprofile") != nil && flag.Lookup("test.coverprofile").Usage == "passed through to KubeArmor" {
// 		t.Error("test flags must not be registered as passthrough flags")
// 	}

// 	args := forwardedArgs("prog")
// 	if args[0] != "prog" {
// 		t.Errorf("args[0] = %q, want program name", args[0])
// 	}
// 	got := map[string]bool{}
// 	for _, a := range args {
// 		got[a] = true
// 		if strings.HasPrefix(a, "-test.") || strings.HasPrefix(a, "-kubeconfig=") {
// 			t.Errorf("non-KubeArmor flag %q must not be forwarded", a)
// 		}
// 	}
// 	for _, want := range []string{
// 		"-ptCriSocket=unix:///run/containerd/containerd.sock",
// 		"-ptUseOCIHooks=true",
// 		"-lsm=bpf,apparmor,selinux",
// 		"-cluster=default",
// 	} {
// 		if !got[want] {
// 			t.Errorf("forwarded args %v are missing %q", args, want)
// 		}
// 	}
// }
