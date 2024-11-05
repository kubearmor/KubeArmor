// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	// node labels
	EnforcerLabel   string = "kubearmor.io/enforcer"
	RuntimeLabel    string = "kubearmor.io/runtime"
	SocketLabel     string = "kubearmor.io/socket"
	RandLabel       string = "kubearmor.io/rand"
	OsLabel         string = "kubernetes.io/os"
	ArchLabel       string = "kubernetes.io/arch"
	BTFLabel        string = "kubearmor.io/btf"
	ApparmorFsLabel string = "kubearmor.io/apparmorfs"
	SecurityFsLabel string = "kubearmor.io/securityfs"
	SeccompLabel    string = "kubearmor.io/seccomp"

	// node taints label
	NotreadyTaint      string = "node.kubernetes.io/not-ready"
	UnreachableTaint   string = "node.kubernetes.io/unreachable"
	UnschedulableTaint string = "node.kubernetes.io/unschedulable"

	DeleteAction string = "DELETE"
	AddAction    string = "ADD"

	SnitchName              string = "kubearmor-snitch"
	KubeArmorSnitchRoleName string = "kubearmor-snitch"
)

var (
	HostPathDirectory         = corev1.HostPathDirectory
	HostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
	HostPathSocket            = corev1.HostPathSocket
	HostPathFile              = corev1.HostPathFile

	Privileged bool = false
	HostPID    bool = false
)

func ShortSHA(s string) string {
	sBytes := []byte(s)

	shaFunc := sha256.New()
	shaFunc.Write(sBytes)
	res := shaFunc.Sum(nil)
	return hex.EncodeToString(res)[:5]
}

var ContainerRuntimeSocketMap = map[string][]string{
	"docker": {
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/docker.sock",
		"/run/docker.sock",
	},
	"containerd": {
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k0s/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/dockershim.sock",
	},
	"cri-o": {
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
	},
}

// ParseImage parses a image string into registry, repository, and tag.
func ParseImage(image string) (string, string, string) {
	// Split the image string into parts
	var registry, repo, tag string

	// Split image by ':'
	parts := strings.Split(image, ":")
	if len(parts) > 2 {
		// Invalid format if there are more than two parts
		return "", "", ""
	}

	// Extract tag if present
	if len(parts) == 2 {
		tag = parts[1]
		image = parts[0]
	} else {
		tag = ""
	}

	// Split image by '/'
	imageParts := strings.Split(image, "/")

	// Handle cases with multiple slashes
	if len(imageParts) > 1 {
		// The last part is the repository
		repo = imageParts[len(imageParts)-1]

		// The registry is everything before the last part
		registry = strings.Join(imageParts[:len(imageParts)-1], "/")
	} else {
		// Handle case with no slashes (assume it is just a repository)
		repo = imageParts[0]
		registry = ""
	}

	// Return results
	return registry, repo, tag
}

// CreateImage generates image string from registry, repository, and tag.
func CreateImage(registry, repo, tag string) string {
	// Construct the image string
	var imageBuilder strings.Builder

	if registry != "" {
		imageBuilder.WriteString(registry)
		imageBuilder.WriteString("/")
	}
	imageBuilder.WriteString(repo)
	if tag != "" {
		imageBuilder.WriteString(":")
		imageBuilder.WriteString(tag)
	}

	return imageBuilder.String()
}
