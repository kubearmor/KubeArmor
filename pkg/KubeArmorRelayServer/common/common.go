// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"os"
	"path/filepath"
)

// ================ //
// == Kubernetes == //
// ================ //

// IsK8sLocal Function
func IsK8sLocal() bool {
	k8sConfig := os.Getenv("KUBECONFIG")
	// #nosec
	if _, err := os.Stat(filepath.Clean(k8sConfig)); err == nil {
		return true
	}

	home := os.Getenv("HOME")
	// #nosec
	if _, err := os.Stat(filepath.Clean(home + "/.kube/config")); err == nil {
		return true
	}

	return false
}

// IsInK8sCluster Function
func IsInK8sCluster() bool {
	if _, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		return true
	}
	// #nosec
	if _, err := os.Stat(filepath.Clean("/run/secrets/kubernetes.io")); err == nil {
		return true
	}

	return false
}

// IsK8sEnv Function
func IsK8sEnv() bool {
	// local
	if IsK8sLocal() {
		return true
	}

	// in-cluster
	if IsInK8sCluster() {
		return true
	}

	return false
}
