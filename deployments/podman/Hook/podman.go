//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"context"
	"strings"

	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/domain/entities"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type podmanHandler struct {
	conn context.Context
}

func newPodmanHandler(socket string) (*podmanHandler, error) {
	conn, err := bindings.NewConnection(context.Background(), socket)
	if err != nil {
		return nil, err
	}
	return &podmanHandler{conn: conn}, nil
}

func (h *podmanHandler) listContainers() ([]types.Container, error) {

	listOptions := &containers.ListOptions{
		Namespace: func(b bool) *bool { return &b }(true),
	}

	containerList, err := containers.List(h.conn, listOptions)
	if err != nil {
		return nil, err
	}

	var containersData []types.Container
	for _, container := range containerList {
		c := containerFromListContainer(container)
		containersData = append(containersData, c)
	}
	return containersData, nil
}

func containerFromListContainer(container entities.ListContainer) types.Container {
	kaContainer := types.Container{}

	kaContainer.ContainerID = container.ID
	if len(container.Names) > 0 {
		kaContainer.ContainerName = container.Names[0]
		kaContainer.EndPointName = container.Names[0]
	}

	kaContainer.NamespaceName = "container_namespace"
	// kaContainer.Privileged = container.Labels["privileged"] == "true" // Assuming a 'privileged' label is set
	labels := []string{}
	labels = append(labels, "namespaceName="+"container_namespace")
	labels = append(labels, "containerType="+"podman")
	labels = append(labels, "kubearmor.io/container.name="+container.Names[0])

	for k, v := range container.Labels {
		labels = append(labels, k+"="+v)
	}
	kaContainer.Labels = strings.Join(labels, ",")
	kaContainer.Status = container.State
	kaContainer.PidNS, kaContainer.MntNS = getNS(container.Pid)

	return kaContainer
}
