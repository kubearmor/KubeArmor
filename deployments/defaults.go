// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package main

import corev1 "k8s.io/api/core/v1"

var kubearmor = "kubearmor"

var serviceAccountName = kubearmor
var clusterRoleBindingName = kubearmor
var relayServiceName = kubearmor
var relayDeploymentName = "kubearmor-relay"
var policyManagerServiceName = "kubearmor-policy-manager-metrics-service"
var policyManagerDeploymentName = "kubearmor-policy-manager"
var hostPolicyManagerServiceName = "kubearmor-host-policy-manager-metrics-service"
var hostPolicyManagerDeploymentName = "kubearmor-host-policy-manager"

type DaemonSetConfig struct {
	Args         []string
	VolumeMounts []corev1.VolumeMount
	Volumes      []corev1.Volume
}

var hostPathDirectory = corev1.HostPathDirectory
var hostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
var hostPathFile = corev1.HostPathFile
var hostPathSocket = corev1.HostPathSocket

// Environment Specific Daemonset Configuration
var defaultConfigs = map[string]DaemonSetConfig{
	"generic": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:      "containerd-storage-path", // containerd storage
				MountPath: "/run/containerd",
				ReadOnly:  true,
			},
			{
				Name:      "docker-storage-path", // docker storage
				MountPath: "/var/lib/docker",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/containerd/containerd.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "containerd-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/containerd",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "docker-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/docker",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"docker": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "docker-sock-path", // docker
				MountPath: "/var/run/docker.sock",
				ReadOnly:  true,
			},
			{
				Name:      "docker-storage-path", // docker storage
				MountPath: "/var/lib/docker",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "docker-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/docker.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "docker-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/docker",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"minikube": {
		Args: []string{},
		VolumeMounts: []corev1.VolumeMount{

			{
				Name:      "docker-sock-path", // docker
				MountPath: "/var/run/docker.sock",
				ReadOnly:  true,
			},
			{
				Name:      "docker-storage-path", // docker storage
				MountPath: "/var/lib/docker",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "docker-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/docker.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "docker-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/docker",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"microk8s": {
		Args: []string{},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/snap/microk8s/common/run/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:      "containerd-storage-path", // containerd storage
				MountPath: "/run/containerd",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/snap/microk8s/common/run/containerd.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "containerd-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/snap/microk8s/common/run/containerd",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"k3s": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:      "containerd-storage-path", // containerd storage
				MountPath: "/run/containerd",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/k3s/containerd/containerd.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "containerd-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/k3s/containerd",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"gke": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:      "containerd-storage-path", // containerd storage
				MountPath: "/run/containerd",
				ReadOnly:  true,
			},
			{
				Name:      "docker-storage-path", // docker storage
				MountPath: "/var/lib/docker",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/containerd/containerd.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "containerd-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/containerd",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "docker-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/docker",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"eks": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "etc-apparmor-d-path",
				MountPath: "/etc/apparmor.d",
			},
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:      "containerd-storage-path", // containerd storage
				MountPath: "/run/containerd",
				ReadOnly:  true,
			},
			{
				Name:      "docker-storage-path", // docker storage
				MountPath: "/var/lib/docker",
				ReadOnly:  true,
			},
		},
		Volumes: []corev1.Volume{
			{
				Name: "etc-apparmor-d-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/apparmor.d",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/containerd/containerd.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "containerd-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/containerd",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
			{
				Name: "docker-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/docker",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
}
