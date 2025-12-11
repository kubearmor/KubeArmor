//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

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
	// TODO: how to get machine id for windows machine
	return "", nil
}
