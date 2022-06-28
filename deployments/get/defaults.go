// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package deployments

import (
	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	corev1 "k8s.io/api/core/v1"
)

var kubearmor = "kubearmor"
var port int32 = 32767

var serviceAccountName = kubearmor
var clusterRoleBindingName = kubearmor
var relayServiceName = kubearmor
var relayDeploymentName = "kubearmor-relay"
var policyManagerServiceName = "kubearmor-policy-manager-metrics-service"
var policyManagerDeploymentName = "kubearmor-policy-manager"
var hostPolicyManagerServiceName = "kubearmor-host-policy-manager-metrics-service"
var hostPolicyManagerDeploymentName = "kubearmor-host-policy-manager"
var AnnotationsControllerServiceName = "kubearmor-annotation-manager-metrics-service"
var AnnotationsControllerDeploymentName = "kubearmor-annotation-manager"

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
}

// Environment Specific Daemonset Configuration
var defaultConfigs = map[string]DaemonSetConfig{
	"generic": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
	"crio": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
			{
				Name:      "crio-sock-path", // crio socket
				MountPath: common.GetCRISocket("crio"),
				ReadOnly:  true,
			},
			{
				Name:      "crio-storage-path", // crio storage - stores all of its data, including containers images, in this directory.
				MountPath: "/var/lib/containers/storage",
				ReadOnly:  true,
			},
			{
				Name:      "crio-state-storage-path", // crio storage -  stores all of its state in this directory.
				MountPath: "/var/run/containers/storage",
				ReadOnly:  true,
			}
		},
		Volumes: []corev1.Volume{
			hostUsrVol,
			apparmorVol,
			{
				Name: "crio-sock-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: common.GetCRISocket("crio"),
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
			{
				Name: "crio-state-storage-path",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/run/containers/storage",
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
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
		Args: []string{
			"-enableKubeArmorHostPolicy",
		}, 
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			gkeHostUsrVolMnt,
			apparmorVolMnt,
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
			gkeHostUsrVol,
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
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
	"aks": {
		Args: []string{
			"-enableKubeArmorHostPolicy",
		},
		Envs: envVar,
		VolumeMounts: []corev1.VolumeMount{
			hostUsrVolMnt,
			apparmorVolMnt,
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
			hostUsrVol,
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
