// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
package monitor

// ImaHash struct
type ImaHash interface {
	Init() error
	Destroy() error
}
