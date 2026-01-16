// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	"os"
	"path/filepath"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
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

	bpfMapsDir := "/sys/fs/bpf/"
	bpfMapsName := []string{"kubearmor_config", "kubearmor_events", "kubearmor_containers", "kubearmor_visibility", "kubearmor_alert_throttle"}
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
			kg.Warnf("Deleting existing map %s. This means previous cleanup failed", path)

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
