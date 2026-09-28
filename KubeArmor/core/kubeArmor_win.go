//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows/registry"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

func (dm *KubeArmorDaemon) IsContainerMonitoringSupported() bool {
	return false
}

func (dm *KubeArmorDaemon) IsK8sModeSupported() bool {
	return false
}

func (dm *KubeArmorDaemon) IsKVMAgentSupported() bool {
	return false
}

func (dm *KubeArmorDaemon) IsPresetSupported() bool {
	return false
}

func (dm *KubeArmorDaemon) GetMachineID() (string, error) {
	// Open the registry key under HKEY_CURRENT_USER
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties`, registry.QUERY_VALUE)
	if err != nil {
		kg.Errf("Error opening registry key: %v\n", err)
		return "", nil
	}
	defer k.Close()

	// Read the LID value which holds the hexadecimal GDID string
	val, _, err := k.GetStringValue("LID")
	if err != nil {
		kg.Errf("Error reading LID value: %v\n", err)
		return "", nil
	}

	// Convert the 16-character hex value into decimal to match the standard `g:<decimal>` format
	num, err := strconv.ParseUint(val, 16, 64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("g:%d", num), nil
}
