// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package usbdevicehandler

import (
	"fmt"
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"k8s.io/utils/ptr"
)

func TestGetUSBLevel(t *testing.T) {
	tests := []struct {
		name     string
		expected int
	}{
		{"1-4.1", 2},
		{"2-4.1.2", 3},
		{"3-1", 1},
		{"2-4.1.2.3", 4},
		{"4", 0}, // invalid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := getUSBLevel(tt.name)
			if level != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, level)
			}
		})
	}
}

func TestParseUSBCodes(t *testing.T) {
	tests := []struct {
		info        string
		class       int32
		subclass    int32
		protocol    int32
		expectError bool
	}{
		{"0/0/0", 0, 0, 0, false},
		{"1/2/3", 1, 2, 3, false},
		{"invalid", 0, 0, 0, true}, // should fail
	}

	for _, tt := range tests {
		t.Run(tt.info, func(t *testing.T) {
			class, subclass, protocol, err := parseUSBCodes(tt.info)
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}
			if class != tt.class || subclass != tt.subclass || protocol != tt.protocol {
				t.Errorf("expected %d/%d/%d, got %d/%d/%d", tt.class, tt.subclass, tt.protocol, class, subclass, protocol)
			}
		})
	}
}

func TestToUint8Safe(t *testing.T) {
	tests := []struct {
		input    int32
		expected uint8
	}{
		{-10, 0},
		{300, 255},
		{128, 128},
		{0, 0},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			result := toUint8Safe(tt.input)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestUpdateHostSecurityPolicies(t *testing.T) {

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// load configuration
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// enable USB Device Handler
	cfg.GlobalCfg.HostPolicy = true
	cfg.GlobalCfg.USBDeviceHandler = true

	// logger
	logger := fd.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// create USB Device Handler
	usbHandler := NewUSBDeviceHandler(logger)
	if usbHandler == nil {
		t.Log("[FAIL] Failed to create USB Device Handler")
		return
	}
	t.Log("[PASS] Created USB Device Handler")

	// test policies
	md := make(map[string]string)
	policies := []tp.HostSecurityPolicy{
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "MASS-STORAGE", SubClass: ptr.To(int32(6)), Action: "Allow"},
				}},
			},
		},
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "8", SubClass: ptr.To(int32(6)), Protocol: ptr.To(int32(80)), Level: ptr.To(int32(2)), Action: "Allow"},
				}},
			},
		},
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "MASS-STORAGE", SubClass: ptr.To(int32(6)), Protocol: ptr.To(int32(80)), Level: ptr.To(int32(2)), Action: "Block"},
				}},
			},
		},
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "0x8", SubClass: ptr.To(int32(6)), Protocol: ptr.To(int32(80)), Action: "Audit"},
				}},
			},
		},
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "HID", Action: "Audit"},
				}},
			},
		},
		{
			Metadata: md,
			Spec: tp.HostSecuritySpec{
				Device: tp.DeviceType{MatchDevice: []tp.DeviceMatchType{
					{Class: "HID", SubClass: ptr.To(int32(1)), Protocol: ptr.To(int32(1)), Action: "Block"},
				}},
			},
		},
	}

	// create rules from policies
	usbHandler.UpdateHostSecurityPolicies(policies)

	// rules
	expectedRules := []EnforcementRule{
		{Class: 8, SubClass: 6, Protocol: 80, Level: 2, Action: "Block", Specificity: 211},
		{Class: 8, SubClass: 6, Protocol: 80, Level: -1, Action: "Audit", Specificity: 111},
		{Class: 3, SubClass: 1, Protocol: 1, Level: -1, Action: "Block", Specificity: 111},
		{Class: 8, SubClass: 6, Protocol: -1, Level: -1, Action: "Allow", Specificity: 110},
		{Class: 3, SubClass: -1, Protocol: -1, Level: -1, Action: "Audit", Specificity: 100},
	}

	// compare generated rules list (in order)
	if len(usbHandler.Rules) != len(expectedRules) {
		t.Log("[FAIL] Number of rules don't match")
	}
	t.Log("[PASS] Number of rules matched")
	for i, r := range usbHandler.Rules {
		if r.Class != expectedRules[i].Class {
			t.Logf("[FAIL] Expected class %d, got %d", expectedRules[i].Class, r.Class)
		}
		if r.SubClass != expectedRules[i].SubClass {
			t.Logf("[FAIL] Expected subclass %d, got %d", expectedRules[i].SubClass, r.SubClass)
		}
		if r.Protocol != expectedRules[i].Protocol {
			t.Logf("[FAIL] Expected protocol %d, got %d", expectedRules[i].Protocol, r.Protocol)
		}
		if r.Level != expectedRules[i].Level {
			t.Logf("[FAIL] Expected level %d, got %d", expectedRules[i].Level, r.Level)
		}
		if r.Action != expectedRules[i].Action {
			t.Logf("[FAIL] Expected action %s, got %s", expectedRules[i].Action, r.Action)
		}
		if r.Specificity != expectedRules[i].Specificity {
			t.Logf("[FAIL] Expected specificity %d, got %d", expectedRules[i].Specificity, r.Specificity)
		}
	}
	t.Log("[PASS] Rules matched")

	// destroy USB Device Handler
	if err := usbHandler.DestroyUSBDeviceHandler(); err != nil {
		t.Log("[FAIL] Failed to destroy USB Device Handler")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Destroyed USB Device Handler")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}
