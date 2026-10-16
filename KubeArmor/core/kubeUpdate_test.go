// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"reflect"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUpdateEndPointWithPodAddCreatesPlaceholderContainers(t *testing.T) {
	dm := NewKubeArmorDaemon()
	pod := newTestK8sPod(
		map[string]string{"cid-1": "ubuntu-1-container"},
		map[string]string{"cid-1": "kubearmor/ubuntu-w-utils:0.1"},
	)

	previousPolicy := cfg.GlobalCfg.Policy
	cfg.GlobalCfg.Policy = false
	t.Cleanup(func() {
		cfg.GlobalCfg.Policy = previousPolicy
	})

	dm.UpdateEndPointWithPod(addEvent, pod)

	container, ok := dm.Containers["cid-1"]
	if !ok {
		t.Fatalf("expected placeholder container to be added")
	}

	if container.NamespaceName != "syscalls" {
		t.Fatalf("expected namespace %q, got %q", "syscalls", container.NamespaceName)
	}

	if container.EndPointName != "ubuntu-1-deployment" {
		t.Fatalf("expected endpoint %q, got %q", "ubuntu-1-deployment", container.EndPointName)
	}

	if container.ContainerName != "ubuntu-1-container" {
		t.Fatalf("expected container name %q, got %q", "ubuntu-1-container", container.ContainerName)
	}
}

func TestUpdateEndPointWithPodSkipsRemovedContainersOnPodUpdate(t *testing.T) {
	dm := NewKubeArmorDaemon()
	dm.Containers["tracked"] = tp.Container{
		NamespaceName:            "syscalls",
		EndPointName:             "ubuntu-1-deployment",
		ContainerName:            "ubuntu-1-container",
		AppArmorProfile:          "kubearmor-syscalls-ubuntu-1-deployment-ubuntu-1-container",
		PolicyEnabled:            tp.KubeArmorPolicyEnabled,
		FileVisibilityEnabled:    true,
		ProcessVisibilityEnabled: true,
		NetworkVisibilityEnabled: true,
	}
	dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
		NamespaceName: "syscalls",
		EndPointName:  "ubuntu-1-deployment",
		ContainerName: "ubuntu-1-container",
		Containers:    []string{"tracked"},
	})

	pod := newTestK8sPod(
		map[string]string{
			"tracked": "ubuntu-1-container",
			"stale":   "ubuntu-1-container",
		},
		map[string]string{
			"tracked": "kubearmor/ubuntu-w-utils:0.1",
			"stale":   "kubearmor/ubuntu-w-utils:0.1",
		},
	)

	previousPolicy := cfg.GlobalCfg.Policy
	cfg.GlobalCfg.Policy = false
	t.Cleanup(func() {
		cfg.GlobalCfg.Policy = previousPolicy
	})

	dm.UpdateEndPointWithPod(updateEvent, pod)

	if _, ok := dm.Containers["stale"]; ok {
		t.Fatalf("expected removed container not to be recreated")
	}

	container, ok := dm.Containers["tracked"]
	if !ok {
		t.Fatalf("expected tracked container to remain present")
	}

	if container.ContainerImage != "kubearmor/ubuntu-w-utils:0.1" {
		t.Fatalf("expected updated image, got %q", container.ContainerImage)
	}

	expectedContainers := []string{"tracked"}
	if !reflect.DeepEqual(dm.EndPoints[0].Containers, expectedContainers) {
		t.Fatalf("expected endpoint containers %v, got %v", expectedContainers, dm.EndPoints[0].Containers)
	}
}

func newTestK8sPod(containers, images map[string]string) tp.K8sPod {
	return tp.K8sPod{
		Metadata: map[string]string{
			"namespaceName": "syscalls",
			"podName":       "ubuntu-1-deployment",
		},
		Annotations: map[string]string{
			"kubearmor-policy":     "enabled",
			"kubearmor-visibility": "process,file,network",
		},
		Labels: map[string]string{
			"container": "ubuntu-1",
		},
		Containers:                 containers,
		ContainerImages:            images,
		PrivilegedContainers:       map[string]struct{}{},
		PrivilegedAppArmorProfiles: map[string]struct{}{},
	}
}
