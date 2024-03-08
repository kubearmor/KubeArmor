// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package deployments

import (
	"strconv"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// GetServiceAccount Function
func GetServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorServiceAccountName,
			Namespace: namespace,
		},
	}
}

// GetClusterRole Function
func GetClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces", "configmaps"},
				Verbs:     []string{"get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets", "daemonsets", "statefulsets"},
				Verbs:     []string{"get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"security.kubearmor.com"},
				Resources: []string{"kubearmorpolicies", "kubearmorhostpolicies"},
				Verbs:     []string{"get", "list", "watch", "update", "delete"},
			},
			{
				NonResourceURLs: []string{"/apis", "/apis/*"},
				Verbs:           []string{"get"},
			},
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
			Name: KubeArmorClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     KubeArmorClusterRoleName,
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
			Name:      RelayServiceName,
			Namespace: namespace,
			Labels:    relayDeploymentLabels,
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
var envVars = []corev1.EnvVar{
	{
		Name:  "ENABLE_STDOUT_LOGS",
		Value: "false",
	},
	{
		Name:  "ENABLE_STDOUT_ALERTS",
		Value: "false",
	},
	{
		Name:  "ENABLE_STDOUT_MSGS",
		Value: "false",
	},
}

// GetRelayDeployment Function
func GetRelayDeployment(namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RelayDeploymentName,
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
					ServiceAccountName: RelayServiceAccountName,
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
							Env: envVars,
						},
					},
				},
			},
		},
	}
}

// GetRelayServiceAccount Function
func GetRelayServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      RelayServiceAccountName,
			Namespace: namespace,
		},
	}
}

// GetRelayClusterRole Function
func GetRelayClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: RelayClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
}

// GetRelayClusterRoleBinding Function
func GetRelayClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: RelayClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     RelayClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      RelayServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

var terminationGracePeriodSeconds = int64(10)

// GenerateDaemonSet Function
func GenerateDaemonSet(env, namespace string) *appsv1.DaemonSet {

	var label = map[string]string{
		"kubearmor-app": kubearmor,
	}
	var privileged = bool(false)
	var terminationGracePeriodSeconds = int64(60)
	var args = []string{
		"-gRPC=" + strconv.Itoa(int(port)),
	}

	var containerVolumeMounts = []corev1.VolumeMount{
		{
			Name:      "bpf",
			MountPath: "/opt/kubearmor/BPF",
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
			Name: "bpf",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "lib-modules-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/lib/modules",
					Type: &hostPathDirectoryOrCreate,
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

	if env == "gke" {
		containerVolumeMounts = append(containerVolumeMounts, gkeHostUsrVolMnt)
		volumes = append(volumes, gkeHostUsrVol)
	} else {
		containerVolumeMounts = append(containerVolumeMounts, hostUsrVolMnt)
		volumes = append(volumes, hostUsrVol)
	}

	args = append(args, defaultConfigs[env].Args...)
	envs := defaultConfigs[env].Envs

	volumeMounts := append(containerVolumeMounts, defaultConfigs[env].VolumeMounts...)
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
					InitContainers: []corev1.Container{
						{
							Name:            "init",
							Image:           "kubearmor/kubearmor-init:stable",
							ImagePullPolicy: "Always",
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										"ALL",
									},
									Add: []corev1.Capability{
										"SETUID",
										"SETGID",
										"SETPCAP",
										"SYS_ADMIN",
										"SYS_PTRACE",
										"MAC_ADMIN",
										"SYS_RESOURCE",
										"IPC_LOCK",
										"CAP_DAC_OVERRIDE",
										"CAP_DAC_READ_SEARCH",
									},
								},
							},
							VolumeMounts: containerVolumeMounts,
						},
					},
					Containers: []corev1.Container{
						{
							Name:            kubearmor,
							Image:           "kubearmor/kubearmor:stable",
							ImagePullPolicy: "Always",
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										"ALL",
									},
									Add: []corev1.Capability{
										"SETUID",
										"SETGID",
										"SETPCAP",
										"SYS_ADMIN",
										"SYS_PTRACE",
										"MAC_ADMIN",
										"SYS_RESOURCE",
										"IPC_LOCK",
										"CAP_DAC_OVERRIDE",
										"CAP_DAC_READ_SEARCH",
									},
								},
							},
							Args: args,
							Env:  envs,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: port,
								},
							},
							VolumeMounts: volumeMounts,
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
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

var KubeArmorControllerLabels = map[string]string{
	"kubearmor-app": "kubearmor-controller",
}

// GetKubeArmorControllerService Function
func GetKubeArmorControllerMetricsService(namespace string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerMetricsServiceName,
			Labels:    KubeArmorControllerLabels,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: KubeArmorControllerLabels,
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Protocol:   corev1.ProtocolTCP,
					Port:       int32(8443),
					TargetPort: intstr.FromString("https"),
				},
			},
		},
	}
}

var KubeArmorControllerCertVolumeDefaultMode = int32(420)

var KubeArmorControllerCertVolume = corev1.Volume{
	Name: "cert",
	VolumeSource: corev1.VolumeSource{
		Secret: &corev1.SecretVolumeSource{
			SecretName:  KubeArmorControllerSecretName,
			DefaultMode: &KubeArmorControllerCertVolumeDefaultMode,
		},
	},
}

var KubeArmorControllerHostPathVolume = corev1.Volume{
	Name: "sys-path",
	VolumeSource: corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{
			Path: "/sys/kernel/security",
			Type: &hostPathDirectory,
		},
	},
}

var KubeArmorControllerAllowPrivilegeEscalation = false

// GetKubeArmorControllerDeployment Function
func GetKubeArmorControllerDeployment(namespace string) *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerDeploymentName,
			Labels:    KubeArmorControllerLabels,
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: KubeArmorControllerLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubearmor-policy": "audited",
						"container.apparmor.security.beta.kubernetes.io/manager":         "unconfined",
						"container.apparmor.security.beta.kubernetes.io/kube-rbac-proxy": "unconfined",
					},
					Labels: KubeArmorControllerLabels,
				},
				Spec: corev1.PodSpec{
					PriorityClassName:  "system-node-critical",
					ServiceAccountName: KubeArmorControllerServiceAccountName,
					Volumes: []corev1.Volume{
						KubeArmorControllerCertVolume,
						KubeArmorControllerHostPathVolume,
					},
					Containers: []corev1.Container{
						{
							Name:  "kube-rbac-proxy",
							Image: "gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0",
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
							Name:  "manager",
							Image: "kubearmor/kubearmor-controller:latest",
							Args: []string{
								"--metrics-bind-address=127.0.0.1:8080",
								"--leader-elect",
								"--health-probe-bind-address=:8081",
							},
							Command: []string{"/manager"},
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: int32(9443),
									Name:          "webhook-server",
									Protocol:      corev1.ProtocolTCP,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      KubeArmorControllerCertVolume.Name,
									ReadOnly:  true,
									MountPath: "/tmp/k8s-webhook-server/serving-certs",
								},
								{
									Name:      KubeArmorControllerHostPathVolume.Name,
									ReadOnly:  true,
									MountPath: "/sys/kernel/security",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &KubeArmorControllerAllowPrivilegeEscalation,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(8081),
									},
								},
								InitialDelaySeconds: int32(15),
								PeriodSeconds:       int32(20),
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstr.FromInt(8081),
									},
								},
								InitialDelaySeconds: int32(5),
								PeriodSeconds:       int32(10),
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("10m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
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

// GetKubeArmorControllerServiceAccount Function
func GetKubeArmorControllerServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerServiceAccountName,
			Namespace: namespace,
		},
	}
}

// GetKubeArmorControllerClusterRole Function
func GetKubeArmorControllerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerClusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"create", "delete", "get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"security.kubearmor.com"},
				Resources: []string{"kubearmorpolicies", "kubearmorhostpolicies"},
				Verbs:     []string{"create", "delete", "get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"security.kubearmor.com"},
				Resources: []string{"kubearmorpolicies/status", "kubearmorhostpolicies/status"},
				Verbs:     []string{"get", "patch", "update"},
			},
		},
	}
}

// GetKubeArmorControllerClusterRoleBinding Function
func GetKubeArmorControllerClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerClusterRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     KubeArmorControllerClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeArmorControllerServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

// GetKubeArmorControllerLeaderElectionRole Function
func GetKubeArmorControllerLeaderElectionRole(namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Role",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerLeaderElectionRoleName,
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create", "delete", "get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"create", "delete", "get", "patch", "list", "watch", "update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}
}

// GetKubeArmorControllerLeaderElectionRoleBinding Function
func GetKubeArmorControllerLeaderElectionRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "RoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerLeaderElectionRoleBindingName,
			Namespace: namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     KubeArmorControllerLeaderElectionRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeArmorControllerServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

// GetKubeArmorControllerProxyRole Function
func GetKubeArmorControllerProxyRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerProxyRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// GetKubeArmorControllerProxyRoleBinding Function
func GetKubeArmorControllerProxyRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerProxyRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     KubeArmorControllerProxyRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeArmorControllerServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

// GetKubeArmorControllerMetricsReaderRole Function
func GetKubeArmorControllerMetricsReaderRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRole",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerMetricsReaderRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				NonResourceURLs: []string{"/metrics"},
				Verbs:           []string{"get"},
			},
		},
	}
}

// GetKubeArmorControllerMetricsReaderRoleBinding Function
func GetKubeArmorControllerMetricsReaderRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: "rbac.authorization.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: KubeArmorControllerMetricsReaderRoleBindingName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     KubeArmorControllerMetricsReaderRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      KubeArmorControllerServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

// GetKubeArmorControllerWebhookService Function
func GetKubeArmorControllerWebhookService(namespace string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerWebhookServiceName,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: KubeArmorControllerLabels,
			Ports: []corev1.ServicePort{
				{
					Port:       443,
					TargetPort: intstr.FromInt(9443),
					Protocol:   "TCP",
				},
			},
		},
	}
}

var KubeArmorControllerMutationFullName = "annotation.kubearmor.com"
var KubeArmorControllerPodMutationPath = "/mutate-pods"
var KubeArmorControllerPodMutationFailurePolicy = admissionregistrationv1.Ignore
var KubeArmorControllerMutationSideEffect = admissionregistrationv1.SideEffectClassNoneOnDryRun

// GetKubeArmorControllerMutationAdmissionConfiguration Function
func GetKubeArmorControllerMutationAdmissionConfiguration(namespace string, caCert []byte) *admissionregistrationv1.MutatingWebhookConfiguration {
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MutatingWebhookConfiguration",
			APIVersion: "admissionregistration.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerMutatingWebhookConfiguration,
			Namespace: namespace,
		},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:                    KubeArmorControllerMutationFullName,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistrationv1.WebhookClientConfig{
					Service: &admissionregistrationv1.ServiceReference{
						Namespace: namespace,
						Name:      KubeArmorControllerWebhookServiceName,
						Path:      &KubeArmorControllerPodMutationPath,
					},
					CABundle: caCert,
				},
				FailurePolicy: &KubeArmorControllerPodMutationFailurePolicy,
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
						},
						Operations: []admissionregistrationv1.OperationType{
							admissionregistrationv1.Create,
							admissionregistrationv1.Update,
						},
					},
				},
				SideEffects: &KubeArmorControllerMutationSideEffect,
				ObjectSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubearmor-app",
							Operator: metav1.LabelSelectorOpDoesNotExist,
						},
					},
				},
			},
		},
	}
}

// GetKubeArmorControllerTLSSecret Functionn
func GetKubeArmorControllerTLSSecret(namespace string, caCert string, tlsCrt string, tlsKey string) *corev1.Secret {
	data := make(map[string]string)
	data["ca.crt"] = caCert
	data["tls.crt"] = tlsCrt
	data["tls.key"] = tlsKey
	return &corev1.Secret{
		Type: corev1.SecretTypeTLS,
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KubeArmorControllerSecretName,
			Namespace: namespace,
			Labels:    KubeArmorControllerLabels,
		},
		StringData: data,
	}
}

var kubearmorConfigLabels = map[string]string{
	"kubearmor-app": "kubearmor-configmap",
}

func GetKubearmorConfigMap(namespace, name string) *corev1.ConfigMap {
	data := make(map[string]string)
	data[cfg.ConfigGRPC] = "32767"
	data[cfg.ConfigVisibility] = "process,network"
	data[cfg.ConfigCluster] = "default"
	data[cfg.ConfigDefaultFilePosture] = "audit"
	data[cfg.ConfigDefaultCapabilitiesPosture] = "audit"
	data[cfg.ConfigDefaultNetworkPosture] = "audit"
	data[cfg.ConfigDefaultPostureLogs] = "true"

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    kubearmorConfigLabels,
		},
		Data: data,
	}
}
