// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package testutils provides shared helpers for KubeArmor tests.
package testutils

import (
	"net"
	"strconv"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

func freeTCPPort(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind test port: %v", err)
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

// ConfigureTestPorts assigns a dynamically allocated TCP port to the test log server.
func ConfigureTestPorts(t testing.TB) {
	t.Helper()
	cfg.GlobalCfg.GRPC = freeTCPPort(t)
}
