// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package runtime

import (
	"os"
	"strings"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
)

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, log zap.SugaredLogger) (string, string) {
	log.Infof("Checking for %s socket\n", k8sRuntime)
	if k8sRuntime != "" {
		for _, path := range common.ContainerRuntimeSocketMap[k8sRuntime] {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				if k8sRuntime == "docker" && strings.Contains(path, "containerd") {
					return "containerd", path
				}
				return k8sRuntime, path
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect k8s runtime location, searching for other runtime sockets")
	for runtime, paths := range common.ContainerRuntimeSocketMap {
		for _, path := range paths {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				return runtime, path
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect runtime")
	return "NA", "NA"
}
