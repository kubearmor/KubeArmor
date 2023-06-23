// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package deployments

import (
	corev1 "k8s.io/api/core/v1"
)

var kubearmor = "kubearmor"
var port int32 = 32767

// K8s Object Name Defaults
var (
	KubeArmorServiceAccountName                      = kubearmor
	KubeArmorClusterRoleBindingName                  = "kubearmor-clusterrolebinding"
	KubeArmorClusterRoleName                         = "kubearmor-clusterrole"
	RelayServiceName                                 = kubearmor
	RelayDeploymentName                              = "kubearmor-relay"
	KubeArmorConfigMapName                           = "kubearmor-config"
	KubeArmorControllerDeploymentName                = "kubearmor-controller"
	KubeArmorControllerServiceAccountName            = KubeArmorControllerDeploymentName
	KubeArmorControllerClusterRoleName               = "kubearmor-controller-clusterrole"
	KubeArmorControllerClusterRoleBindingName        = "kubearmor-controller-clusterrolebinding"
	KubeArmorControllerLeaderElectionRoleName        = "kubearmor-controller-leader-election-role"
	KubeArmorControllerLeaderElectionRoleBindingName = "kubearmor-controller-leader-election-rolebinding"
	KubeArmorControllerProxyRoleName                 = "kubearmor-controller-proxy-role"
	KubeArmorControllerProxyRoleBindingName          = "kubearmor-controller-proxy-rolebinding"
	KubeArmorControllerMetricsReaderRoleName         = "kubearmor-controller-metrics-reader-role"
	KubeArmorControllerMetricsReaderRoleBindingName  = "kubearmor-controller-metrics-reader-rolebinding"
	KubeArmorControllerMetricsServiceName            = "kubearmor-controller-metrics-service"
	KubeArmorControllerWebhookServiceName            = "kubearmor-controller-webhook-service"
	KubeArmorControllerSecretName                    = "kubearmor-controller-webhook-server-cert"
	KubeArmorControllerMutatingWebhookConfiguration  = "kubearmor-controller-mutating-webhook-configuration"
)

// DaemonSetConfig Structure
type DaemonSetConfig struct {
	Args         []string
	Envs         []corev1.EnvVar
	VolumeMounts []corev1.VolumeMount
	Volumes      []corev1.Volume
}

var hostPathDirectory = corev1.HostPathDirectory
var hostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
var hostPathFile = corev1.HostPathFile
var hostPathSocket = corev1.HostPathSocket
var hostContainerStorageMountPropagation = corev1.MountPropagationHostToContainer

var gkeHostUsrVolMnt = corev1.VolumeMount{
	Name:      "usr-src-path", // /usr -> /media/root/usr (read-only) check issue #579 for details
	MountPath: "/media/root/usr",
	ReadOnly:  true,
}

var gkeHostUsrVol = corev1.Volume{ // check #579 why GKE is handled separately
	Name: "usr-src-path",
	VolumeSource: corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{
			Path: "/usr",
			Type: &hostPathDirectory,
		},
	},
}

var hostUsrVolMnt = corev1.VolumeMount{
	Name:      "usr-src-path", // /usr/src (read-only)
	MountPath: "/usr/src",
	ReadOnly:  true,
}

var hostUsrVol = corev1.Volume{
	Name: "usr-src-path",
	VolumeSource: corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{
			Path: "/usr/src",
			Type: &hostPathDirectory,
		},
	},
}

var apparmorVolMnt = corev1.VolumeMount{
	Name:      "etc-apparmor-d-path",
	MountPath: "/etc/apparmor.d",
}

var apparmorVol = corev1.Volume{
	Name: "etc-apparmor-d-path",
	VolumeSource: corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{
			Path: "/etc/apparmor.d",
			Type: &hostPathDirectoryOrCreate,
		},
	},
}

var envVar = []corev1.EnvVar{
	{
		Name: "KUBEARMOR_NODENAME",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "spec.nodeName",
			},
		},
	},
	{
		Name: "KUBEARMOR_NAMESPACE",
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: "metadata.namespace",
			},
		},
	},
}

// Environment Specific Daemonset Configuration
var defaultConfigs = map[string]DaemonSetConfig{
	"generic": {
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
	"oke": {
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "crio-sock-path", // crio socket
				MountPath: "/var/run/crio/crio.sock",
				ReadOnly:  true,
			},
			{
				Name:             "crio-storage-path", // crio storage - stores all of its data, including containers images, in this directory.
				MountPath:        "/var/lib/containers/storage",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
			{
				Name: "crio-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/crio/crio.sock",
						Type: &hostPathSocket,
					},
				},
			},
			{
				Name: "crio-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/lib/containers/storage",
						Type: &hostPathDirectoryOrCreate,
					},
				},
			},
		},
	},
	"docker": {
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "docker-sock-path", // docker
				MountPath: "/var/run/docker.sock",
				ReadOnly:  true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "docker-sock-path", // docker
				MountPath: "/var/run/docker.sock",
				ReadOnly:  true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/snap/microk8s/common/run/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
	"bottlerocket": {
		Args: []string{
			"-criSocket=unix:///run/dockershim.sock",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/run/dockershim.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
			{
				Name: "containerd-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/run/dockershim.sock",
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
	"aks": {
		Args: []string{},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			apparmorVolMnt,
			{
				Name:      "containerd-sock-path", // containerd
				MountPath: "/var/run/containerd/containerd.sock",
				ReadOnly:  true,
			},
			{
				Name:             "containerd-storage-path", // containerd storage
				MountPath:        "/run/containerd",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
			{
				Name:             "docker-storage-path", // docker storage
				MountPath:        "/var/lib/docker",
				MountPropagation: &hostContainerStorageMountPropagation,
				ReadOnly:         true,
			},
		},
		Volumes: []corev1.Volume{
			apparmorVol,
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
