// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// fakeCrioRuntimeClient answers ListContainers like CRI-O does: it applies the
// request's state filter, and with no filter it returns every container,
// including exited ones.
type fakeCrioRuntimeClient struct {
	pb.RuntimeServiceClient
	containers []*pb.Container
	lastReq    *pb.ListContainersRequest
}

func (f *fakeCrioRuntimeClient) ListContainers(_ context.Context, in *pb.ListContainersRequest, _ ...grpc.CallOption) (*pb.ListContainersResponse, error) {
	f.lastReq = in
	resp := &pb.ListContainersResponse{}
	for _, c := range f.containers {
		if in.GetFilter().GetState() != nil && in.GetFilter().GetState().GetState() != c.State {
			continue
		}
		resp.Containers = append(resp.Containers, c)
	}
	return resp, nil
}

// TestGetCrioContainersSkipsExited checks that exited containers are not
// returned. If they were, MonitorCrioEvents would treat them as new on every
// pass, fail to read their (gone) PID, and retry them every 50ms forever.
func TestGetCrioContainersSkipsExited(t *testing.T) {
	fake := &fakeCrioRuntimeClient{containers: []*pb.Container{
		{Id: "running", State: pb.ContainerState_CONTAINER_RUNNING},
		{Id: "exited", State: pb.ContainerState_CONTAINER_EXITED},
		{Id: "created", State: pb.ContainerState_CONTAINER_CREATED},
	}}
	ch := &CrioHandler{client: fake, containers: map[string]struct{}{}}

	got, err := ch.GetCrioContainers()
	if err != nil {
		t.Fatalf("GetCrioContainers() error = %v", err)
	}

	if fake.lastReq.GetFilter().GetState().GetState() != pb.ContainerState_CONTAINER_RUNNING {
		t.Fatalf("ListContainers request should filter on CONTAINER_RUNNING, got %v", fake.lastReq.GetFilter())
	}
	if len(got) != 1 {
		t.Fatalf("expected only the running container, got %v", got)
	}
	if _, ok := got["running"]; !ok {
		t.Fatalf("running container missing from result: %v", got)
	}
}

// TestCrioExitedContainerIsDestroyed checks that a container which exits
// drops out of the running list and is reported as deleted, so the normal
// destroy path cleans it up.
func TestCrioExitedContainerIsDestroyed(t *testing.T) {
	fake := &fakeCrioRuntimeClient{containers: []*pb.Container{
		{Id: "app", State: pb.ContainerState_CONTAINER_RUNNING},
	}}
	ch := &CrioHandler{client: fake, containers: map[string]struct{}{}}

	first, err := ch.GetCrioContainers()
	if err != nil {
		t.Fatalf("GetCrioContainers() error = %v", err)
	}
	if n := ch.GetNewCrioContainers(first); len(n) != 1 {
		t.Fatalf("expected app to be new, got %v", n)
	}
	ch.GetDeletedCrioContainers(first)

	fake.containers[0].State = pb.ContainerState_CONTAINER_EXITED

	second, err := ch.GetCrioContainers()
	if err != nil {
		t.Fatalf("GetCrioContainers() error = %v", err)
	}
	if n := ch.GetNewCrioContainers(second); len(n) != 0 {
		t.Fatalf("exited container must not be new again, got %v", n)
	}
	deleted := ch.GetDeletedCrioContainers(second)
	if _, ok := deleted["app"]; !ok {
		t.Fatalf("exited container should be reported as deleted, got %v", deleted)
	}
}
