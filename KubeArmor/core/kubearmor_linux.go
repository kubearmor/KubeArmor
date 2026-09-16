//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"os"
	"strings"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

func (dm *KubeArmorDaemon) IsContainerMonitoringSupported() bool {
	return true
}

func (dm *KubeArmorDaemon) IsK8sModeSupported() bool {
	return true
}

func (dm *KubeArmorDaemon) IsKVMAgentSupported() bool {
	return true
}

func (dm *KubeArmorDaemon) IsPresetSupported() bool {
	return true
}

func (dm *KubeArmorDaemon) GetMachineID() (string, error) {
	id, err := os.ReadFile(cfg.GlobalCfg.MachineIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(id), "\n"), nil
}
