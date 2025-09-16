// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"context"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type containerdHandler struct {
	client *containerd.Client
}

func newContainerdHandler(socket string) (handler, error) {
	client, err := containerd.New(socket, containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return nil, err
	}

	return &containerdHandler{client: client}, nil
}

func (h *containerdHandler) listContainers(ctx context.Context) ([]types.Container, error) {
	containers := make([]types.Container, 0)
	containerList, err := h.client.Containers(ctx)
	if err != nil {
		return nil, err
	}
	for _, container := range containerList {
		c, err := containerFromContainerdResult(ctx, container)
		if err != nil {
			return nil, err
		}

		containers = append(containers, c)
	}
	return containers, nil
}
func (h *containerdHandler) close() error {
	return h.client.Close()
}

func containerFromContainerdResult(ctx context.Context, container containerd.Container) (types.Container, error) {
	spec, err := container.Spec(ctx)
	if err != nil {
		return types.Container{}, err
	}
	task, err := container.Task(ctx, nil)
	if err != nil && !errdefs.IsNotFound(err) {
		return types.Container{}, err
	}
	info, err := container.Info(ctx)
	if err != nil {
		return types.Container{}, err
	}
	c := types.Container{
		ContainerID:     info.ID,
		ContainerName:   info.ID,
		ContainerImage:  info.Image,
		NamespaceName:   "Unknown",
		EndPointName:    "Unknown",
		AppArmorProfile: spec.Process.ApparmorProfile,
	}
	if task != nil {
		c.PidNS, c.MntNS = getNS(int(task.Pid()))
	}
	containerLabels := info.Labels
	if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
		c.NamespaceName = val
	}
	if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
		c.EndPointName = val
	}
	return c, nil
}
