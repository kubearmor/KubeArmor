// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func init() {
	buildinfo.PrintBuildDetails()
}

func isKubeArmorBpfMap(name string) bool {
	return strings.HasPrefix(name, "kubearmor")
}

func cleanupBpfMaps(bpfMapsDir string, removeFn func(string) error) error {
	entries, err := os.ReadDir(bpfMapsDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isKubeArmorBpfMap(entry.Name()) {
			path := filepath.Join(bpfMapsDir, entry.Name())
			if err := removeFn(path); err != nil {
				kg.Errf("Failed to delete BPF map %s: %v", path, err)
			} else {
				kg.Warnf("Deleting existing map %s. This indicates previous cleanup failed", path)
			}
		}
	}
	return nil
}

func main() {
	if os.Geteuid() != 0 {
		if os.Getenv("KUBEARMOR_UBI") == "" {
			kg.Printf("Need to have root privileges to run %s\n", os.Args[0])
			return
		}
	}
	// initial clean up

	bpfMapsDir := "/sys/fs/bpf/"

	if err := cleanupBpfMaps(bpfMapsDir, kl.RemoveSafe); err != nil {
		kg.Errf("Failed to read BPF map directory: %v", err)
		return
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		kg.Err(err.Error())
		return
	}

	if err := os.Chdir(dir); err != nil {
		kg.Err(err.Error())
		return
	}

	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	core.KubeArmor()
}
