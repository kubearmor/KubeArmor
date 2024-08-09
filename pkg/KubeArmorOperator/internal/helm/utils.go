// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package helm

import (
	"fmt"
	"strings"
)

type InstallError struct {
	msg string
	err string
}

func (e *InstallError) Error() string {
	return fmt.Sprintf("installError: %s: %v", e.msg, e.err)
}

type UpgradeError struct {
	msg string
	err string
}

func (e *UpgradeError) Error() string {
	return fmt.Sprintf("upgradeError: %s: %v", e.msg, e.err)
}

func IsReconcilableError(err error) bool {
	return strings.Contains(err.Error(), "nodes are not processed or kubearmorconfig")
}
