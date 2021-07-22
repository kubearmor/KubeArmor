// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"net/http"
	_ "net/http/pprof"

	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func main() {
	// == //

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

	// == //

	// options (string)
	clusterPtr := flag.String("cluster", "", "cluster name")
	gRPCPtr := flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr := flag.String("logPath", "none", "log file path, {path|stdout|none}")
	logFilterPtr := flag.String("logFilter", "policy", "Filter for what kinds of alerts and logs to receive, {policy|system|all}")

	// options (boolean)
	enableAuditdPtr := flag.Bool("enableAuditd", false, "enabling Auditd")
	enableHostPolicyPtr := flag.Bool("enableHostPolicy", false, "enabling host policies")
	enableEnforcerPerPodPtr := flag.Bool("enableEnforcerPerPod", false, "enabling the enforcer per pod")

	// profile option
	pprofPtr := flag.String("pprof", "none", "pprof port number")

	flag.Parse()

	if *pprofPtr != "none" {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:"+*pprofPtr, nil))
		}()
	}

	// == //

	core.KubeArmor(*clusterPtr, *gRPCPtr, *logPathPtr, *logFilterPtr, *enableAuditdPtr, *enableHostPolicyPtr, *enableEnforcerPerPodPtr)

	// == //
}
