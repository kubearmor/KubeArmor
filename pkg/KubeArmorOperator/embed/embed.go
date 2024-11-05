// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package embed

import (
	"embed"
)

//go:embed *.tgz
var EmbedFs embed.FS

//go:embed *.yaml
var CRDFs embed.FS
