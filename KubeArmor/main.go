// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	"os"
	"path/filepath"
	"strings"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func init() {
	buildinfo.PrintBuildDetails()
}

func main() {
	if os.Geteuid() != 0 {
		if os.Getenv("KUBEARMOR_UBI") == "" {
			kg.Printf("Need to have root privileges to run %s\n", os.Args[0])
			return
		}
	}
	// initial clean up
	// Delete all pinned BPF maps starting with "kubearmor"
	bpfMapsDir := "/sys/fs/bpf/"

	entries, err := os.ReadDir(bpfMapsDir)
	if err != nil {
		kg.Errf("Failed to read BPF map directory: %v", err)
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), "kubearmor") {
			/* This should not be triggered in ideal cases,
			if this is triggered that means there is incomplete cleanup process
			from the last installation */
			path := filepath.Join(bpfMapsDir, entry.Name())
			err := os.Remove(path)
			if err != nil {
				kg.Errf("Failed to delete BPF map %s: %v", path, err)
			} else {
				kg.Warnf("Deleting existing map %s. This indicates previous cleanup failed", path)
			}
		}
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
