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
var enableKubeArmorPolicyPtr, enableKubeArmorHostPolicyPtr, enableKubeArmorVMPtr, coverageTestPtr *bool
var defaultFilePosturePtr, defaultCapabilitiesPosturePtr, defaultNetworkPosturePtr, hostDefaultCapabilitiesPosturePtr, hostDefaultNetworkPosturePtr, hostDefaultFilePosturePtr *string

func init() {
	// options (string)
	clusterPtr = flag.String("cluster", "", "cluster name")

	// options (string)
	gRPCPtr = flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr = flag.String("logPath", "none", "log file path")

	// options (string)
	defaultFilePosturePtr = flag.String("defaultFilePosture", "block", "configuring default enforcement action in global file context {allow|audit|block}")
	defaultNetworkPosturePtr = flag.String("defaultNetworkPosture", "block", "configuring default enforcement action in global network context {allow|audit|block}")
	defaultCapabilitiesPosturePtr = flag.String("defaultCapabilitiesPosture", "block", "configuring default enforcement action in global capability context {allow|audit|block}")

	hostDefaultFilePosturePtr = flag.String("hostDefaultFilePosture", "block", "configuring default enforcement action in global file context {allow|audit|block}")
	hostDefaultNetworkPosturePtr = flag.String("hostDefaultNetworkPosture", "block", "configuring default enforcement action in global network context {allow|audit|block}")
	hostDefaultCapabilitiesPosturePtr = flag.String("hostDefaultCapabilitiesPosture", "block", "configuring default enforcement action in global capability context {allow|audit|block}")

	// options (boolean)
	enableKubeArmorPolicyPtr = flag.Bool("enableKubeArmorPolicy", true, "enabling KubeArmorPolicy")
	enableKubeArmorHostPolicyPtr = flag.Bool("enableKubeArmorHostPolicy", true, "enabling KubeArmorHostPolicy")
	enableKubeArmorVMPtr = flag.Bool("enableKubeArmorVm", false, "enabling KubeArmorVM")

	// options (boolean)
	coverageTestPtr = flag.Bool("coverageTest", true, "enabling CoverageTest")
}

// TestMain - test to drive external testing coverage
func TestMain(t *testing.T) {
	// Reset Test Flags before executing main
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Set os args to set flags in main
	os.Args = []string{"cmd", "--cluster", *clusterPtr, "--gRPC", *gRPCPtr, "--logPath", *logPathPtr,
		"--defaultFilePosture", *defaultFilePosturePtr,
		"--defaultNetworkPosture", *defaultNetworkPosturePtr,
		"--defaultCapabilitiesPosture", *defaultCapabilitiesPosturePtr,
		"--hostDefaultFilePosture", *hostDefaultFilePosturePtr,
		"--hostDefaultNetworkPosture", *hostDefaultNetworkPosturePtr,
		"--hostDefaultCapabilitiesPosture", *hostDefaultCapabilitiesPosturePtr,
		"--enableKubeArmorPolicy", strconv.FormatBool(*enableKubeArmorPolicyPtr),
		"--enableKubeArmorHostPolicy", strconv.FormatBool(*enableKubeArmorHostPolicyPtr),
		"--enableKubeArmorVm", strconv.FormatBool(*enableKubeArmorVMPtr),
		"--coverageTest", strconv.FormatBool(*coverageTestPtr)}

	t.Log("[INFO] Executed KubeArmor")
	main()
	t.Log("[INFO] Terminated KubeArmor")
}
