// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUpdateContainerNonK8sDestroyAppArmorCleanup(t *testing.T) {
	// Disable policy and state agent to isolate the container update state machine
	cfg.GlobalCfg.Policy = false
	cfg.GlobalCfg.StateAgent = false

	dm := &KubeArmorDaemon{
		EndPoints:            []tp.EndPoint{},
		EndPointsLock:        &sync.RWMutex{},
		ContainersLock:       &sync.RWMutex{},
		Containers:           make(map[string]tp.Container),
		SecurityPoliciesLock: &sync.RWMutex{},
		SecurityPolicies:     []tp.SecurityPolicy{},
		SystemMonitor: &mon.SystemMonitor{
			NsMap:            make(map[mon.NsKey]string),
			NsMapLock:        &sync.RWMutex{},
			BpfMapLock:       &sync.RWMutex{},
			NamespacePidsMap: make(map[string]mon.NsVisibility),
		},
		Logger: &fd.Feeder{
			SecurityPolicies:     make(map[string]tp.MatchPolicies),
			SecurityPoliciesLock: &sync.RWMutex{},
		},
	}

	containerID := "nonk8s-cid-101"
	containerName := "my-standalone-service"
	profileName := "kubearmor_my-standalone-service"

	container := tp.Container{
		ContainerID:     containerID,
		ContainerName:   containerName,
		NamespaceName:   "default",
		AppArmorProfile: profileName,
		Labels:          "app=standalone",
	}

	// 1. Create container
	if err := dm.UpdateContainer(containerID, container, "create"); err != nil {
		t.Fatalf("failed to create non-K8s container: %v", err)
	}

	// Verify endpoint and profile registered.
	dm.EndPointsLock.RLock()
	if len(dm.EndPoints) != 1 {
		dm.EndPointsLock.RUnlock()
		t.Fatalf("expected 1 endpoint, got %d", len(dm.EndPoints))
	}
	if len(dm.EndPoints[0].AppArmorProfiles) != 1 || dm.EndPoints[0].AppArmorProfiles[0] != profileName {
		t.Errorf("expected AppArmor profile %q in endpoint, got %v", profileName, dm.EndPoints[0].AppArmorProfiles)
	}
	dm.EndPointsLock.RUnlock()

	// 2. Destroy container
	if err := dm.UpdateContainer(containerID, container, "destroy"); err != nil {
		t.Fatalf("failed to destroy non-K8s container: %v", err)
	}

	// Verify container removed from container map
	dm.ContainersLock.RLock()
	if _, ok := dm.Containers[containerID]; ok {
		t.Errorf("container %s still exists in dm.Containers map", containerID)
	}
	dm.ContainersLock.RUnlock()

	// Verify AppArmor profile entry was removed from the endpoint
	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()
	for _, ep := range dm.EndPoints {
		for _, prof := range ep.AppArmorProfiles {
			if prof == profileName {
				t.Errorf("BUG VERIFIED: AppArmor profile %q leaked in endpoint after container destroy!", profileName)
			}
		}
	}
}
