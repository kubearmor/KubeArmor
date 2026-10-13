// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUpdateContainerRulesStaleRevisionSkip(t *testing.T) {
	be := &BPFEnforcer{
		ContainerMap:     make(map[string]ContainerKV),
		ContainerMapLock: new(sync.RWMutex),
	}

	const containerID = "test-container"
	be.ContainerMap[containerID] = ContainerKV{
		AppliedPolicyRevision: 2,
	}

	be.UpdateContainerRules(containerID, []tp.SecurityPolicy{}, tp.DefaultPosture{}, 1)

	if be.ContainerMap[containerID].AppliedPolicyRevision != 2 {
		t.Fatalf("expected AppliedPolicyRevision to remain 2, got %d", be.ContainerMap[containerID].AppliedPolicyRevision)
	}
}

func TestUpdateContainerRulesHostRevisionBypass(t *testing.T) {
	be := &BPFEnforcer{
		ContainerMap:     make(map[string]ContainerKV),
		ContainerMapLock: new(sync.RWMutex),
	}

	const containerID = "test-container"
	be.ContainerMap[containerID] = ContainerKV{
		AppliedPolicyRevision: 5,
	}

	// revision=0 is the host-policy path and must not be rejected by the endpoint revision guard.
	be.UpdateContainerRules(containerID, []tp.SecurityPolicy{}, tp.DefaultPosture{}, 0)

	if be.ContainerMap[containerID].AppliedPolicyRevision != 5 {
		t.Fatalf("expected host revision bypass to leave AppliedPolicyRevision at 5, got %d", be.ContainerMap[containerID].AppliedPolicyRevision)
	}
}
