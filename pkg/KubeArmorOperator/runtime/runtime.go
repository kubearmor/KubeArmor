// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package runtime

import (
	"os"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
)

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, log zap.SugaredLogger) (string, string) {
	log.Infof("Checking for %s socket\n", k8sRuntime)
	if k8sRuntime != "" {
		for _, path := range common.ContainerRuntimeSocketMap[k8sRuntime] {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				return k8sRuntime, path
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Could'nt detect k8s runtime localtion, searching for other runtime sockets")
	for runtime, paths := range common.ContainerRuntimeSocketMap {
		for _, path := range paths {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				return runtime, path
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Could'nt detect runtime")
	return "NA", "NA"
}

func DetectRuntimeStorage(pathPrefix, runtime string, log zap.SugaredLogger) string {

	for _, storagelocaltion := range common.RuntimeStorageVolumes[runtime] {
		if _, err := os.Stat(pathPrefix + storagelocaltion); err == nil {
			return storagelocaltion
		}
	}
	return "NA"
}
