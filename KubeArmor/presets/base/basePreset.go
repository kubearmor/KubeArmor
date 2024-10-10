// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package base

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const (
	PRESET_ENFORCER string = "PRESET-"
)

type PresetType uint8

const (
	FilelessExec PresetType = 1
	AnonMapExec  PresetType = 2
)

type PresetAction uint32

const (
	Audit PresetAction = 1
	Block PresetAction = 2
)

type BasePreset struct {
	Logger  *fd.Feeder
	Monitor *mon.SystemMonitor
}

type InnerKey struct {
	Path   [256]byte
	Source [256]byte
}

type EventPreset struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32

	Retval int64

	Comm [80]byte

	Data InnerKey
}

type BasePresetInterface interface {
	Name() string
	// Init() error
	RegisterPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) (BasePresetInterface, error)
	RegisterContainer(containerID string, pidns, mntns uint32)
	UnregisterContainer(containerID string)
	UpdateSecurityPolicies(endPoint tp.EndPoint)
	Destroy() error
}
