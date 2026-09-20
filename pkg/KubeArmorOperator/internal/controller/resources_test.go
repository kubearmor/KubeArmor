// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controller

import (
	"strings"
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/stretchr/testify/assert"
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
