// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"testing"
)

var clusterPtr, gRPCPtr, logPathPtr, enableAuditdPtr, enableHostPolicyPtr, enableEnforcerPerPodPtr, pprofPtr *string

func init() {
	// options (string)
	clusterPtr = flag.String("cluster", "", "cluster name")
	gRPCPtr = flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr = flag.String("logPath", "none", "log file path")

	// options (boolean)
	enableAuditdPtr = flag.String("enableAuditd", "false", "enabling Auditd")
	enableHostPolicyPtr = flag.String("enableHostPolicy", "false", "enabling host policies")
	enableEnforcerPerPodPtr = flag.String("enableEnforcerPerPod", "false", "enabling the enforcer per pod")

	// profile option
	pprofPtr = flag.String("pprof", "none", "pprof port number")
}

// TestMain - test to drive external testing coverage
func TestMain(t *testing.T) {
	// Reset Test Flags before executing main
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set os args to set flags in main
	os.Args = []string{"cmd", "-cluster", *clusterPtr, "-gRPC", *gRPCPtr, "-logPath", *logPathPtr, "-enableAuditd", *enableAuditdPtr, "-enableHostPolicy", *enableHostPolicyPtr, "-enableEnforcerPerPod", *enableEnforcerPerPodPtr, "-pprof", *pprofPtr}
	main()
}
