// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package operator

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func SnitchClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubearmor-snitch-clusterrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"patch"},
			},
		},
	}
}

func ControllerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubearmor-controller-clusterrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"security.kubearmor.com"},
				Resources: []string{"kubearmorhostpolicies", "kubearmorpolicies"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
}

func BpfContainerdClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kubearmor-bpf-containerd-clusterrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps", "namespaces", "nodes"},
				Verbs:     []string{"list", "watch"},
			},
			{
				APIGroups: []string{"security.kubearmor.com"},
				Resources: []string{"kubearmorpolicies"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
}
