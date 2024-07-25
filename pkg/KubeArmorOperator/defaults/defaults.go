// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package defaults

import (
	"crypto/sha256"
	"encoding/hex"

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
