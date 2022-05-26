// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func main() {
	if os.Geteuid() != 0 {
		kg.Printf("Need to have root privileges to run %s\n", os.Args[0])
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

	if finfo, err := os.Stat(os.Args[0]); err == nil {
		stat := finfo.Sys().(*syscall.Stat_t)
		kg.Printf("Build Time: %v", time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)))
	}

	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	core.KubeArmor()
}
