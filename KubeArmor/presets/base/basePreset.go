// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package base provides interface for presets
package base

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const (
	// PRESET_ENFORCER prefix for a preset
	PRESET_ENFORCER string = "PRESET-"
)

// PresetType represents type of a preset
type PresetType uint8

// PresetAction preset action
type PresetAction uint32

const (
	// Audit action
	Audit PresetAction = 1
	// Block action
	Block PresetAction = 2
)

// Preset type
type Preset struct {
	Logger  *fd.Feeder
	Monitor *mon.SystemMonitor
}

// InnerKey type
type InnerKey struct {
	Path   [256]byte
	Source [256]byte
}

// EventPreset type
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

	// exec events
	ExecID uint64
}

// PresetInterface interface
type PresetInterface interface {
	Name() string
	// Init() error
	RegisterPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) (PresetInterface, error)
	RegisterContainer(containerID string, pidns, mntns uint32)
	UnregisterContainer(containerID string)
	UpdateSecurityPolicies(endPoint tp.EndPoint)
	Destroy() error
}
