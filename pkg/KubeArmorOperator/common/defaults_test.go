// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"slices"
	"strconv"
	"testing"
)

func TestGetOCIHooks(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "operator", value: "yes", expected: true},
		{name: "snitch", value: "true", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBEARMOR_OCI_HOOKS", tt.value)

			if got := GetOCIHooks(); got != tt.expected {
				t.Errorf("GetOCIHooks() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetSensorGRPCPort(t *testing.T) {
	defaultArgs := KubeArmorArgs
	defer func() { KubeArmorArgs = defaultArgs }()

	tests := []struct {
		name     string
		args     []string
		expected int32
	}{
		{name: "default args", args: defaultArgs, expected: 32767},
		{name: "custom port", args: []string{"-gRPC=28080", "-tlsEnabled=false"}, expected: 28080},
		{name: "no gRPC arg", args: []string{"-tlsEnabled=false"}, expected: 32767},
		{name: "invalid port", args: []string{"-gRPC=abc"}, expected: 32767},
		{name: "out of range port", args: []string{"-gRPC=70000"}, expected: 32767},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			KubeArmorArgs = tt.args
			if got := GetSensorGRPCPort(); got != tt.expected {
				t.Errorf("GetSensorGRPCPort() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestDefaultRelayGRPCPortMatchesSensor(t *testing.T) {
	want := "-" + ConfigRelayGRPCPort + "=" + strconv.Itoa(int(GetSensorGRPCPort()))
	if !slices.Contains(KubeArmorRelayArgs, want) {
		t.Errorf("default relay args %v do not contain %q", KubeArmorRelayArgs, want)
	}
}
