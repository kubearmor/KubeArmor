// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package recommend

import (
	"embed"
)

//go:embed *.yaml
var CRDFs embed.FS
