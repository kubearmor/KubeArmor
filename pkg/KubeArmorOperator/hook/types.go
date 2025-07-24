// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"context"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type handler interface {
	listContainers(ctx context.Context) ([]types.Container, error)
	close() error
}
