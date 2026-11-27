// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"strings"
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestSetCriSocket(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		label   string
		args    []string
		want    []string
	}{
		{
			name:    "k3s socket is passed with its host path",
			runtime: "containerd",
			label:   "run_k3s_containerd_containerd.sock",
			args:    []string{"-gRPC=32767"},
			want:    []string{"-gRPC=32767", "-criSocket=unix:///run/k3s/containerd/containerd.sock"},
		},
		{
			name:    "replaces an existing flag",
			runtime: "cri-o",
			label:   "var_run_crio_crio.sock",
			args:    []string{"-criSocket=unix:///run/other.sock", "-gRPC=32767"},
			want:    []string{"-criSocket=unix:///var/run/crio/crio.sock", "-gRPC=32767"},
		},
		{
			name:    "unknown socket leaves args untouched",
			runtime: "containerd",
			label:   "no_such_socket",
			args:    []string{"-gRPC=32767"},
			want:    []string{"-gRPC=32767"},
		},
		{
			name:    "unknown runtime leaves args untouched",
			runtime: "none",
			label:   "run_k3s_containerd_containerd.sock",
			args:    []string{"-gRPC=32767"},
			want:    []string{"-gRPC=32767"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			setCriSocket(tt.runtime, tt.label, &args)
			assert.Equal(t, tt.want, args)
		})
	}

	assert.NotPanics(t, func() { setCriSocket("containerd", "run_k3s_containerd_containerd.sock", nil) })
}

// The path passed via -criSocket must exist inside the container, i.e. it has to
// live under the directory that genRuntimeVolumes mounts.
func TestCriSocketIsUnderMountedDir(t *testing.T) {
	for runtime, sockets := range common.ContainerRuntimeSocketMap {
		if runtime == "nri" {
			continue
		}
		for _, socket := range sockets {
			label := strings.ReplaceAll(socket[1:], "/", "_")

			vols, mounts := genRuntimeVolumes(runtime, label, "")
			if assert.Len(t, vols, 1, socket) && assert.Len(t, mounts, 1, socket) {
				assert.Equal(t, vols[0].HostPath.Path, mounts[0].MountPath, "%s: mounted at a different path than the host path", socket)
				assert.True(t, strings.HasPrefix(socket, mounts[0].MountPath+"/"), "%s is not under %s", socket, mounts[0].MountPath)
			}

			var args []string
			setCriSocket(runtime, label, &args)
			assert.Equal(t, []string{"-criSocket=unix://" + socket}, args)
		}
	}
}

func TestControllerDeploymentNeedsUpdate(t *testing.T) {
	previous := common.IfNodeWithSecurtiyFs
	common.IfNodeWithSecurtiyFs = false
	t.Cleanup(func() { common.IfNodeWithSecurtiyFs = previous })

	newDeployment := func(args []string, tolerations []corev1.Toleration) *appsv1.Deployment {
		return &appsv1.Deployment{
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers:  []corev1.Container{{Name: "manager", Args: args}},
						Tolerations: tolerations,
					},
				},
			},
		}
	}
	args := []string{"--leader-elect", "--webhook-port=9443"}
	toleration := corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "security", Effect: corev1.TaintEffectNoSchedule}

	tests := []struct {
		name     string
		deployed *appsv1.Deployment
		desired  *appsv1.Deployment
		want     bool
	}{
		{
			name:     "nothing changed",
			deployed: newDeployment(args, []corev1.Toleration{toleration}),
			desired:  newDeployment(args, []corev1.Toleration{toleration}),
			want:     false,
		},
		{
			name:     "nil and empty tolerations are the same",
			deployed: newDeployment(args, nil),
			desired:  newDeployment(args, []corev1.Toleration{}),
			want:     false,
		},
		{
			name:     "toleration added",
			deployed: newDeployment(args, nil),
			desired:  newDeployment(args, []corev1.Toleration{toleration}),
			want:     true,
		},
		{
			name:     "toleration removed",
			deployed: newDeployment(args, []corev1.Toleration{toleration}),
			desired:  newDeployment(args, nil),
			want:     true,
		},
		{
			name:     "args changed",
			deployed: newDeployment(args, nil),
			desired:  newDeployment([]string{"--leader-elect", "--webhook-port=9444"}, nil),
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, controllerDeploymentNeedsUpdate(tt.deployed, tt.desired))
		})
	}
}
