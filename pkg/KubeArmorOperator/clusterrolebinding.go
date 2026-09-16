// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package operator

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func clusterRoleBinding(name, roleName, saName, namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     roleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: namespace,
			},
		},
	}
}

func SnitchClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return clusterRoleBinding(
		"kubearmor-snitch-clusterrole-binding",
		"kubearmor-snitch-clusterrole",
		"kubearmor-snitch",
		namespace,
	)
}

func ControllerClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return clusterRoleBinding(
		"kubearmor-controller-clusterrole-binding",
		"kubearmor-controller-clusterrole",
		"kubearmor-controller",
		namespace,
	)
}

func BpfContainerdClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return clusterRoleBinding(
		"kubearmor-bpf-containerd-clusterrole-binding",
		"kubearmor-bpf-containerd-clusterrole",
		"kubearmor",
		namespace,
	)
}
