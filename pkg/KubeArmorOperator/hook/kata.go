// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	kataHookLockFile      = "/tmp/kubearmor_kata_hook.lock"
	kataOutputBufferFile  = "/tmp/output.json"
	kataKubeArmorInfoFile = "/tmp/id.json"
)

func isPoststopHookPath(p string) bool {
	if p == "" {
		return false
	}
	return filepath.Base(filepath.Dir(filepath.Clean(p))) == "poststop"
}

func resolveKataRootfs(state specs.State, spec specs.Spec, specLoaded bool) string {
	if specLoaded && spec.Root != nil && spec.Root.Path != "" {
		if filepath.IsAbs(spec.Root.Path) {
			return spec.Root.Path
		}
		if state.Bundle != "" {
			return filepath.Join(state.Bundle, spec.Root.Path)
		}
	}
	if state.Bundle != "" {
		candidate := filepath.Join(state.Bundle, "rootfs")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return filepath.Join("/var/run/kata-containers/shared/containers", state.ID, "rootfs")
}

func loadKataKubeArmorInfo() (kataKubeArmorInfo, bool) {
	data, err := os.ReadFile(kataKubeArmorInfoFile)
	if err != nil {
		return kataKubeArmorInfo{}, false
	}
	var info kataKubeArmorInfo
	if err := json.Unmarshal(data, &info); err != nil || info.Rootfs == "" {
		return kataKubeArmorInfo{}, false
	}
	return info, true
}

func saveKataKubeArmorInfo(info kataKubeArmorInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return writeFileAtomic(kataKubeArmorInfoFile, data, 0600)
}

func loadKataContainers() (map[string]types.Container, error) {
	containers := make(map[string]types.Container)
	data, err := os.ReadFile(kataOutputBufferFile)
	if err != nil {
		if os.IsNotExist(err) {
			return containers, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", kataOutputBufferFile, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return containers, nil
	}
	if err := json.Unmarshal(data, &containers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", kataOutputBufferFile, err)
	}
	return containers, nil
}

func persistAndSyncKataContainers(containers map[string]types.Container, kaInfo kataKubeArmorInfo, kaKnown bool) error {
	data, err := json.Marshal(containers)
	if err != nil {
		return fmt.Errorf("failed to marshal containers: %w", err)
	}
	if err := writeFileAtomic(kataOutputBufferFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", kataOutputBufferFile, err)
	}
	if kaKnown {
		return syncKataContainersToRootfs(containers, kaInfo.Rootfs)
	}
	return nil
}

func syncKataContainersToRootfs(containers map[string]types.Container, rootfs string) error {
	data, err := json.Marshal(containers)
	if err != nil {
		return fmt.Errorf("failed to marshal containers: %w", err)
	}
	targetPath := filepath.Join(rootfs, hookOutputFile)
	if err := writeFileAtomic(targetPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write hook output (%s): %w", targetPath, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, ".kubearmor-hook-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func isKataPoststop(state specs.State) bool {
	if strings.EqualFold(string(state.Status), string(specs.StateStopped)) {
		return true
	}
	if isPoststopHookPath(os.Args[0]) {
		return true
	}
	if execPath, err := os.Executable(); err == nil && isPoststopHookPath(execPath) {
		return true
	}
	return false
}
