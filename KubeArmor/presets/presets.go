// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package presets contains preset rules components
package presets

import (
	"github.com/kubearmor/KubeArmor/KubeArmor/presets/base"
)

// Preset struct
type Preset struct {
	base.Preset

	List map[string]base.PresetInterface
}
