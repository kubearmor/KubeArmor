// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package deployments

import (
	"strconv"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// GetServiceAccount Function
func GetServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
		},
	}
}

// GetClusterRoleBinding Function
func GetClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterRoleBindingName,
			Namespace: namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      kubearmor,
				Namespace: namespace,
			},
		},
	}
}

// GetRelayService Function
func GetRelayService(namespace string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      relayServiceName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: relayDeploymentLabels,
			Ports: []corev1.ServicePort{
				{
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
					Protocol:   "TCP",
				},
			},
		},
	}
}

var replicas = int32(1)

var relayDeploymentLabels = map[string]string{
	"kubearmor-app": "kubearmor-relay",
}

// GetRelayDeployment Function
func GetRelayDeployment(namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      relayDeploymentName,
			Labels:    relayDeploymentLabels,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: relayDeploymentLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubearmor-policy": "audited",
					},
					Labels: relayDeploymentLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: kubearmor,
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					Containers: []corev1.Container{
						{
							Name:  "kubearmor-relay-server",
							Image: "kubearmor/kubearmor-relay-server:latest",
							//imagePullPolicy is Always since image has latest tag
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: port,
								},
							},
						},
					},
				},
			},
		},
	}
}

var terminationGracePeriodSeconds = int64(10)

var policyManagerDeploymentLabels = map[string]string{
	"kubearmor-app": "kubearmor-policy-manager",
}

// GetPolicyManagerService Function
func GetPolicyManagerService(namespace string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyManagerServiceName,
			Labels:    policyManagerDeploymentLabels,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: policyManagerDeploymentLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       8443,
					TargetPort: intstr.FromString("https"),
				},
			},
		},
	}
}

// GetPolicyManagerDeployment Function
func GetPolicyManagerDeployment(namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyManagerDeploymentName,
			Labels:    policyManagerDeploymentLabels,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: policyManagerDeploymentLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubearmor-policy": "audited",
					},
					Labels: policyManagerDeploymentLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: kubearmor,
					Containers: []corev1.Container{
						{
							Name:  "kube-rbac-proxy",
							Image: "gcr.io/kubebuilder/kube-rbac-proxy:v0.5.0",
							Args: []string{
								"--secure-listen-address=0.0.0.0:8443",
								"--upstream=http://127.0.0.1:8080/",
								"--logtostderr=true",
								"--v=10",
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8443,
									Name:          "https",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("40Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("20Mi"),
								},
							},
						},
						{
							Name:  "kubearmor-policy-manager",
							Image: "kubearmor/kubearmor-policy-manager:latest",
							Args: []string{
								"--metrics-addr=127.0.0.1:8080",
								"--enable-leader-election",
							},
							Command: []string{"/manager"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("40Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("20Mi"),
								},
							},
						},
					},
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
				},
			},
		},
	}
}

var hostPolicyManagerDeploymentLabels = map[string]string{
	"kubearmor-app": "kubearmor-host-policy-manager",
}

// GetHostPolicyManagerService Function
func GetHostPolicyManagerService(namespace string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      hostPolicyManagerServiceName,
			Labels:    hostPolicyManagerDeploymentLabels,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: hostPolicyManagerDeploymentLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       8443,
					TargetPort: intstr.FromString("https"),
				},
			},
		},
	}
}

// GetHostPolicyManagerDeployment Function
func GetHostPolicyManagerDeployment(namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      hostPolicyManagerDeploymentName,
			Labels:    hostPolicyManagerDeploymentLabels,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: hostPolicyManagerDeploymentLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubearmor-policy": "audited",
					},
					Labels: hostPolicyManagerDeploymentLabels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: kubearmor,
					Containers: []corev1.Container{
						{
							Name:  "kube-rbac-proxy",
							Image: "gcr.io/kubebuilder/kube-rbac-proxy:v0.5.0",
							Args: []string{
								"--secure-listen-address=0.0.0.0:8443",
								"--upstream=http://127.0.0.1:8080/",
								"--logtostderr=true",
								"--v=10",
							},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8443,
									Name:          "https",
								},
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("40Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("20Mi"),
								},
							},
						},
						{
							Name:  "kubearmor-host-policy-manager",
							Image: "kubearmor/kubearmor-host-policy-manager:latest",
							Args: []string{
								"--metrics-addr=127.0.0.1:8080",
								"--enable-leader-election",
							},
							Command: []string{"/manager"},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("40Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("20Mi"),
								},
							},
						},
					},
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
				},
			},
		},
	}
}

// GenerateDaemonSet Function
func GenerateDaemonSet(env, namespace string) *appsv1.DaemonSet {

	var label = map[string]string{
		"kubearmor-app": kubearmor,
	}
	var privileged = bool(true)
	var terminationGracePeriodSeconds = int64(30)
	var args = []string{
		"-gRPC=" + strconv.Itoa(int(port)),
		"-logPath=/tmp/kubearmor.log",
	}
	var volumeMounts = []corev1.VolumeMount{
		{
			Name:      "usr-src-path", //BPF (read-only)
			MountPath: "/usr/src",
			ReadOnly:  true,
		},
		{
			Name:      "lib-modules-path", //BPF (read-only)
			MountPath: "/lib/modules",
			ReadOnly:  true,
		},
		{
			Name:      "sys-fs-bpf-path", //BPF (read-write)
			MountPath: "/sys/fs/bpf",
		},
		{
			Name:      "sys-kernel-security-path", //LSM (read-only)
			MountPath: "/sys/kernel/security",
		},
		{
			Name:      "sys-kernel-debug-path", //BPF (read-only)
			MountPath: "/sys/kernel/debug",
		},
		{
			Name:      "os-release-path", //BPF (read-only)
			MountPath: "/media/root/etc/os-release",
			ReadOnly:  true,
		},
	}

	var volumes = []corev1.Volume{
		{
			Name: "usr-src-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/usr/src",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "lib-modules-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/lib/modules",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "sys-fs-bpf-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys/fs/bpf",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "sys-kernel-security-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys/kernel/security",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "sys-kernel-debug-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys/kernel/debug",
					Type: &hostPathDirectory,
				},
			},
		},
		{
			Name: "os-release-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/etc/os-release",
					Type: &hostPathFile,
				},
			},
		},
	}

	args = append(args, defaultConfigs[env].Args...)

	volumeMounts = append(volumeMounts, defaultConfigs[env].VolumeMounts...)
	volumes = append(volumes, defaultConfigs[env].Volumes...)

	return &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubearmor,
			Labels:    label,
			Namespace: namespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: label,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: label,
					Annotations: map[string]string{
						"container.apparmor.security.beta.kubernetes.io/kubearmor": "unconfined",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: kubearmor,
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					Tolerations: []corev1.Toleration{
						{
							Operator: "Exists",
						},
					},
					HostPID:       true,
					HostNetwork:   true,
					RestartPolicy: "Always",
					DNSPolicy:     "ClusterFirstWithHostNet",
					Containers: []corev1.Container{
						{
							Name:            kubearmor,
							Image:           "kubearmor/kubearmor:stable",
							ImagePullPolicy: "Always",
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Args: args,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: port,
								},
							},
							VolumeMounts: volumeMounts,
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"/bin/bash",
											"-c",
											"if [ -z $(pgrep kubearmor) ]; then exit 1; fi;",
										},
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       10,
							},
							TerminationMessagePolicy: "File",
							TerminationMessagePath:   "/dev/termination-log",
						},
					},
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
					Volumes:                       volumes,
				},
			},
		},
	}
}
