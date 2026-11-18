// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
)

func podWith(statuses ...corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: statuses}}
}

func running(name, id string) corev1.ContainerStatus {
	return corev1.ContainerStatus{Name: name, ContainerID: id, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}
}

func TestSnitchContainerID(t *testing.T) {
	// fix 1: empty / not-yet-published statuses are errors, not "NA"
	_, err := snitchContainerID(podWith(), "snitch")
	assert.Error(t, err)

	// fix 1: running but ID empty
	_, err = snitchContainerID(podWith(running("snitch", "")), "snitch")
	assert.Error(t, err)

	// fix 2: terminated (stale) container is ignored
	stale := corev1.ContainerStatus{Name: "snitch", ContainerID: "docker://old", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}}
	_, err = snitchContainerID(podWith(stale), "snitch")
	assert.Error(t, err)

	// fix 2: picked by name, not by index
	id, err := snitchContainerID(podWith(running("sidecar", "docker://side"), running("snitch", "docker://abc")), "snitch")
	assert.NoError(t, err)
	assert.Equal(t, "abc", id)
}

func TestWaitForSnitchContainerID(t *testing.T) {
	calls := 0
	get := func(context.Context) (*corev1.Pod, error) {
		calls++
		switch calls {
		case 1:
			return nil, errors.New("api blip")
		case 2:
			return podWith(), nil
		default:
			return podWith(running("snitch", "containerd://xyz")), nil
		}
	}
	id, err := waitForSnitchContainerID(context.Background(), get, "snitch", 5, time.Millisecond, *zap.NewNop().Sugar())
	assert.NoError(t, err)
	assert.Equal(t, "xyz", id)
	assert.Equal(t, 3, calls)

	_, err = waitForSnitchContainerID(context.Background(), func(context.Context) (*corev1.Pod, error) { return podWith(), nil }, "snitch", 2, time.Millisecond, *zap.NewNop().Sugar())
	assert.Error(t, err)
}

func TestIsCriDockerdSocket(t *testing.T) {
	assert.True(t, isCriDockerdSocket("/run/cri-dockerd.sock"))
	assert.True(t, isCriDockerdSocket("unix:///var/run/cri-dockerd.sock"))
	assert.False(t, isCriDockerdSocket("/run/containerd/containerd.sock"))
	assert.False(t, isCriDockerdSocket("/run/crio/crio.sock"))
}

func TestValidateDetection(t *testing.T) {
	assert.NoError(t, ValidateDetection("containerd", "/run/containerd/containerd.sock"))
	assert.NoError(t, ValidateDetection("docker", "/run/docker.sock"))
	assert.NoError(t, ValidateDetection("cri-o", "/run/crio/crio.sock"))
	// fix 8: the cri-dockerd-as-cri-o combination must be rejected
	assert.Error(t, ValidateDetection("cri-o", "/run/cri-dockerd.sock"))
	assert.Error(t, ValidateDetection("nri", "/run/nri/nri.sock"))
	assert.Error(t, ValidateDetection("unknown", "/x.sock"))
}
