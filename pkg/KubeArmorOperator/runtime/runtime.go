// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
)

func DetectNRI(pathPrefix string) (string, error) {
	for _, path := range common.ContainerRuntimeSocketMap["nri"] {
		if _, err := os.Stat(filepath.Clean(pathPrefix + path)); err == nil || os.IsPermission(err) {
			return path, nil
		} else {
			log.Warnf("%s", err)
		}
	}
	return "NA", fmt.Errorf("NRI not available")
}

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, explicitSocket string, log zap.SugaredLogger) (string, string, string) {
	if explicitSocket != "" {
		log.Infof("Using explicit socket file: %s", explicitSocket)

		hostPath := strings.TrimPrefix(explicitSocket, "unix://")
		if !filepath.IsAbs(hostPath) {
			log.Errorf("Explicit socket path must be absolute: %s", explicitSocket)
			return "NA", "NA", "NA"
		}

		hostPath = filepath.Clean(hostPath)
		checkPath := filepath.Clean(pathPrefix + hostPath)

		if _, err := os.Stat(checkPath); err == nil || os.IsPermission(err) {
			runtime := determineRuntimeFromSocket(hostPath)

			if (runtime == "docker" && strings.Contains(hostPath, "containerd")) || runtime == "containerd" {
				if nriPath, err := DetectNRI(pathPrefix); err == nil {
					return runtime, hostPath, nriPath
				} else {
					log.Warnf("NRI detection failed: %s", err)
				}
			}

			return runtime, hostPath, ""
		} else {
			log.Errorf("Explicit socket file not accessible: %s", err)
			return "NA", "NA", "NA"
		}
	}

	log.Infof("Checking for %s socket\n", k8sRuntime)
	if k8sRuntime != "" {
		for _, path := range common.ContainerRuntimeSocketMap[k8sRuntime] {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				if (k8sRuntime == "docker" && strings.Contains(path, "containerd")) || k8sRuntime == "containerd" {
					if nriPath, err := DetectNRI(pathPrefix); err == nil {
						return k8sRuntime, path, nriPath
					} else {
						log.Warnf("%s", err)
					}
				}
				k8sRuntime := determineRuntimeFromSocket(path)
				return k8sRuntime, path, ""
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect k8s runtime location, searching for other runtime sockets")
	for runtime, paths := range common.ContainerRuntimeSocketMap {
		for _, path := range paths {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				runtime = determineRuntimeFromSocket(path)
				return runtime, path, ""
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect runtime")
	return "NA", "NA", "NA"
}

// Determine runtime from socket path
func determineRuntimeFromSocket(socketPath string) string {
	socketPath = strings.ToLower(socketPath)

	if strings.Contains(socketPath, "docker") {
		return "docker"
	} else if strings.Contains(socketPath, "containerd") {
		return "containerd"
	} else if strings.Contains(socketPath, "cri-o") || strings.Contains(socketPath, "crio") {
		return "cri-o"
	}
	return "containerd"
}
