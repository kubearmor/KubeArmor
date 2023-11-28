// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	"os"
	"path/filepath"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// GitCommit represents build-time info for git commit
var GitCommit string

// GitBranch represents build-time info for git branch
var GitBranch string

// BuildDate represents build-time info for build date
var BuildDate string

func printBuildDetails() {
	if GitCommit == "" {
		return
	}
	kg.Printf("BUILD-INFO: commit: %v, branch: %v, date: %v",
		GitCommit, GitBranch, BuildDate)
}

func init() {
	printBuildDetails()
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
	bpfMapsName := []string{"kubearmor_config", "events", "kubearmor_contianers", "kubearmor_visibility"}
	for _, mp := range bpfMapsName {
		path := bpfMapsDir + mp
		/* This should not be triggered in ideal cases,
		if this is triggered that means there is incomplete cleanup process
		from the last installation */
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			err = os.Remove(path)
			if err != nil {
				kg.Err(err.Error())
			}
			kg.Warnf("Deleteing existing map %s. This means previous cleanup was failed", path)

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
