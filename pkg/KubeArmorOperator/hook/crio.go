// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type containerInfo struct {
	SandboxID   string     `json:"sandboxID"`
	Pid         int        `json:"pid"`
	RuntimeSpec specs.Spec `json:"runtimeSpec"`
	Privileged  bool       `json:"privileged"`
}

type crioHandler struct {
	client runtime.RuntimeServiceClient
	conn   *grpc.ClientConn
}

func newCRIOHandler(socket string) (handler, error) {
	conn, err := grpc.Dial(
		socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	client := runtime.NewRuntimeServiceClient(conn)
	return &crioHandler{client: client, conn: conn}, nil
}

func (h *crioHandler) close() error {
	return h.conn.Close()

}

func (h *crioHandler) listContainers(ctx context.Context) ([]types.Container, error) {
	containers := make([]types.Container, 0)
	containersList, err := h.client.ListContainers(ctx, &runtime.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	for _, container := range containersList.GetContainers() {
		c, err := h.getContainer(ctx, container.GetId())
		if err != nil {
			log.Printf("failed to get container %q: %s", container.GetId(), err.Error())
			continue
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func (h *crioHandler) getContainer(ctx context.Context, id string) (types.Container, error) {
	containerStatus, err := h.client.ContainerStatus(
		ctx,
		&runtime.ContainerStatusRequest{ContainerId: id, Verbose: true},
	)
	if err != nil {
		return types.Container{}, err
	}
	c, err := containerFromContainerStatus(containerStatus.Status, containerStatus.Info["info"])
	if err != nil {
		return types.Container{}, err
	}
	return c, nil
}

func containerFromContainerStatus(status *runtime.ContainerStatus, info string) (types.Container, error) {
	container := types.Container{}

	container.ContainerID = status.Id
	container.ContainerName = status.Metadata.Name

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	containerLabels := status.Labels
	if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
		container.NamespaceName = val
	}
	if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
		container.EndPointName = val
	}

	var containerInfo containerInfo
	err := json.Unmarshal([]byte(info), &containerInfo)
	if err != nil {
		return container, err
	}

	container.AppArmorProfile = containerInfo.RuntimeSpec.Process.ApparmorProfile
	container.Privileged = containerInfo.Privileged

	container.PidNS, container.MntNS = getNS(containerInfo.Pid)

	return container, nil
}
