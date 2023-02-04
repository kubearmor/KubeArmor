// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package main is the entrypoint to initializing the armor
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

var GitCommit string
var GitBranch string
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

	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	if cfg.GlobalCfg.EnablePPROF {

		mux := http.NewServeMux()

		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

		server := &http.Server{
			Addr:    "0.0.0.0:" + cfg.GlobalCfg.PPROF,
			Handler: mux,
		}

		if err := server.ListenAndServe(); err != nil {
			kg.Err(err.Error() + "\nCould not expose a pprof server for debugging")
		} else {
			fmt.Println("pprof server is running on http://0.0.0.0:" + cfg.GlobalCfg.PPROF)
		}
	}

	core.KubeArmor()
}
