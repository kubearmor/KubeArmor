// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import "strings"

const kubernetesContainerNameLabel = "io.kubernetes.container.name"

// resolveContainerName returns the Kubernetes container name when the runtime
// exposes it, otherwise it falls back to the runtime-derived name.
func resolveContainerName(runtimeName string, labels map[string]string) string {
	if labels != nil {
		if containerName, ok := labels[kubernetesContainerNameLabel]; ok && containerName != "" {
			return containerName
		}
	}

	return strings.TrimPrefix(runtimeName, "/")
}
