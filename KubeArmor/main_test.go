// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package main

import (
	"flag"
	"os"
	"strconv"
	"testing"
)

var clusterPtr, gRPCPtr, logPathPtr *string
var enableKubeArmorPolicyPtr, enableKubeArmorHostPolicyPtr, enableKubeArmorVMPtr *bool

func init() {
	// options (string)
	clusterPtr = flag.String("cluster", "", "cluster name")
	gRPCPtr = flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr = flag.String("logPath", "none", "log file path")

	// options (boolean)
	enableKubeArmorPolicyPtr = flag.Bool("enableKubeArmorPolicy", false, "enabling KubeArmorPolicy")
	enableKubeArmorHostPolicyPtr = flag.Bool("enableKubeArmorHostPolicy", false, "enabling KubeArmorHostPolicy")
	enableKubeArmorVMPtr = flag.Bool("enableKubeArmorVm", false, "enabling KubeArmorVM")
}

// TestMain - test to drive external testing coverage
func TestMain(t *testing.T) {
	// Reset Test Flags before executing main
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set os args to set flags in main
	os.Args = []string{"cmd", "--cluster", *clusterPtr, "--gRPC", *gRPCPtr, "--logPath", *logPathPtr,
		"--enableKubeArmorPolicy", strconv.FormatBool(*enableKubeArmorPolicyPtr),
		"--enableKubeArmorHostPolicy", strconv.FormatBool(*enableKubeArmorHostPolicyPtr),
		"--enableKubeArmorVm", strconv.FormatBool(*enableKubeArmorVMPtr)}

	// run KubeArmor
	main()
}
