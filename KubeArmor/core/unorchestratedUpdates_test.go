// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	yl "sigs.k8s.io/yaml"
)

func saveRestoreBackupCfg(t *testing.T, restorePath string) {
	t.Helper()
	origRestore := cfg.GlobalCfg.RestorePath
	origPolicyDir := cfg.PolicyDir
	origPolicy := cfg.GlobalCfg.Policy
	origHostPolicy := cfg.GlobalCfg.HostPolicy
	origNetPolicy := cfg.GlobalCfg.NetworkPolicyEnforcer
	origK8sEnv := cfg.GlobalCfg.K8sEnv
	origHost := cfg.GlobalCfg.Host

	cfg.GlobalCfg.RestorePath = restorePath
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = true
	cfg.GlobalCfg.NetworkPolicyEnforcer = true
	cfg.GlobalCfg.K8sEnv = false
	cfg.GlobalCfg.Host = "test-host"

	t.Cleanup(func() {
		cfg.GlobalCfg.RestorePath = origRestore
		_ = origPolicyDir
		cfg.GlobalCfg.Policy = origPolicy
		cfg.GlobalCfg.HostPolicy = origHostPolicy
		cfg.GlobalCfg.NetworkPolicyEnforcer = origNetPolicy
		cfg.GlobalCfg.K8sEnv = origK8sEnv
		cfg.GlobalCfg.Host = origHost
	})
}

func TestBackupAndRestoreKubeArmorPolicies_RoundTrip(t *testing.T) {
	baseDir := t.TempDir()

	for _, tc := range []struct {
		name        string
		restorePath string
	}{
		{name: "without trailing slash", restorePath: filepath.Join(baseDir, "no-slash")},
		{name: "with trailing slash", restorePath: filepath.Join(baseDir, "with-slash") + "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveRestoreBackupCfg(t, tc.restorePath)

			src := newTestKataDaemon(t, false)
			src.backupKubeArmorContainerPolicy(tp.SecurityPolicy{
				Metadata: map[string]string{"policyName": "ksp-test", "namespaceName": "test-host"},
				Spec: tp.SecuritySpec{
					Selector: tp.SelectorType{MatchLabels: map[string]string{"app": "nginx"}},
					Action:   "Block",
				},
			})
			src.backupKubeArmorHostPolicy(tp.HostSecurityPolicy{
				Metadata: map[string]string{"policyName": "hsp-test"},
				Spec: tp.HostSecuritySpec{
					NodeSelector: tp.NodeSelectorType{MatchLabels: map[string]string{"kubernetes.io/hostname": "test-host"}},
					Action:       "Audit",
				},
			})
			src.backupKubeArmorNetworkPolicy(tp.NetworkSecurityPolicy{
				Metadata: map[string]string{"policyName": "nsp-test"},
				Spec: tp.NetworkSecuritySpec{
					Selector: tp.SelectorType{MatchLabels: map[string]string{"app": "nginx"}},
					Action:   "Allow",
				},
			})

			// Verify written files are YAML (not JSON)
			for _, fname := range []string{"ksp-test.yaml", "hsp-test.yaml", "nsp-test.yaml"} {
				raw, err := os.ReadFile(filepath.Join(tc.restorePath, fname))
				if err != nil {
					t.Fatalf("expected backup file %s: %v", fname, err)
				}
				if strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
					t.Fatalf("expected YAML output for %s, got JSON-like %q", fname, string(raw))
				}
				var parsed map[string]any
				if err := yl.Unmarshal(raw, &parsed); err != nil {
					t.Fatalf("failed to YAML-unmarshal %s: %v", fname, err)
				}
			}

			dst := newTestKataDaemon(t, false)
			dst.restoreKubeArmorPolicies()

			if len(dst.SecurityPolicies) != 1 || dst.SecurityPolicies[0].Metadata["policyName"] != "ksp-test" {
				t.Fatalf("expected ksp-test restored, got %+v", dst.SecurityPolicies)
			}
			if len(dst.HostSecurityPolicies) != 1 || dst.HostSecurityPolicies[0].Metadata["policyName"] != "hsp-test" {
				t.Fatalf("expected hsp-test restored, got %+v", dst.HostSecurityPolicies)
			}
			if len(dst.NetworkSecurityPolicies) != 1 || dst.NetworkSecurityPolicies[0].Metadata["policyName"] != "nsp-test" {
				t.Fatalf("expected nsp-test restored, got %+v", dst.NetworkSecurityPolicies)
			}
		})
	}
}

func TestRestoreKubeArmorPolicies_UnknownOrEmptyKindNotTreatedAsHostPolicy(t *testing.T) {
	dir := t.TempDir()
	saveRestoreBackupCfg(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "cm.yaml"), []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-cm\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nokind.yaml"), []byte("foo: bar\n"), 0600); err != nil {
		t.Fatal(err)
	}

	dm := newTestKataDaemon(t, false)
	dm.restoreKubeArmorPolicies()

	if len(dm.HostSecurityPolicies) != 0 {
		t.Fatalf("expected 0 host policies from unknown/empty kinds, got %d (%+v)", len(dm.HostSecurityPolicies), dm.HostSecurityPolicies)
	}
	if len(dm.SecurityPolicies) != 0 || len(dm.NetworkSecurityPolicies) != 0 {
		t.Fatalf("expected 0 security/network policies, got ksp=%d nsp=%d", len(dm.SecurityPolicies), len(dm.NetworkSecurityPolicies))
	}
}

func TestRestoreKubeArmorPolicies_SkipsNonYAMLSubdirsAndMalformedFiles(t *testing.T) {
	validKSP, err := yl.Marshal(struct {
		Kind     string            `json:"kind"`
		Metadata metav1.ObjectMeta `json:"metadata"`
		Spec     tp.SecuritySpec   `json:"spec"`
	}{
		Kind:     KubeArmorPolicy,
		Metadata: metav1.ObjectMeta{Name: "valid-ksp"},
		Spec: tp.SecuritySpec{
			Selector: tp.SelectorType{MatchLabels: map[string]string{"app": "demo"}},
			Action:   "Block",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("non-YAML files and subdirectory skipped", func(t *testing.T) {
		dir := t.TempDir()
		saveRestoreBackupCfg(t, dir)

		if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("just text"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte{0x00, 0x01, 0xff}, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blob.bin"), []byte{0xff, 0xfe, 0x00, 0x42}, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), validKSP, 0600); err != nil {
			t.Fatal(err)
		}

		dm := newTestKataDaemon(t, false)
		dm.restoreKubeArmorPolicies()

		if len(dm.SecurityPolicies) != 1 || dm.SecurityPolicies[0].Metadata["policyName"] != "valid-ksp" {
			t.Fatalf("expected valid-ksp restored alongside skipped files, got %+v", dm.SecurityPolicies)
		}
	})

	t.Run("malformed YAML alongside valid YAML", func(t *testing.T) {
		dir := t.TempDir()
		saveRestoreBackupCfg(t, dir)

		if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("kind: [unclosed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "valid.yml"), validKSP, 0600); err != nil {
			t.Fatal(err)
		}

		dm := newTestKataDaemon(t, false)
		dm.restoreKubeArmorPolicies()

		if len(dm.SecurityPolicies) != 1 || dm.SecurityPolicies[0].Metadata["policyName"] != "valid-ksp" {
			t.Fatalf("expected valid-ksp restored despite broken.yaml, got %+v", dm.SecurityPolicies)
		}
	})
}

func TestRestoreKubeArmorPolicies_MissingRestorePath(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "does-not-exist")
	saveRestoreBackupCfg(t, missingPath)

	dm := newTestKataDaemon(t, false)
	dm.restoreKubeArmorPolicies()

	if len(dm.SecurityPolicies) != 0 || len(dm.HostSecurityPolicies) != 0 || len(dm.NetworkSecurityPolicies) != 0 {
		t.Fatalf("expected no policies restored from missing directory")
	}
}

