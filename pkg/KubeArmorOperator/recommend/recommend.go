// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package recommend

import (
	"embed"
)

//go:embed *.yaml
var CRDFs embed.FS
