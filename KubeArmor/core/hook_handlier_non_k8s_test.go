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

// newTestDaemon creates a minimal KubeArmorDaemon for unit testing
func newTestDaemon(secPolicies []tp.SecurityPolicy) *KubeArmorDaemon {
	cfg.GlobalCfg.Policy = false
	cfg.GlobalCfg.StateAgent = false

	return &KubeArmorDaemon{
		EndPoints:            []tp.EndPoint{},
		EndPointsLock:        &sync.RWMutex{},
		ContainersLock:       &sync.RWMutex{},
		Containers:           make(map[string]tp.Container),
		SecurityPoliciesLock: &sync.RWMutex{},
		SecurityPolicies:     secPolicies,
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
}

// testPolicy returns a SecurityPolicy matching the given identity
func testPolicy(identity string) tp.SecurityPolicy {
	return tp.SecurityPolicy{
		Metadata: map[string]string{
			"namespaceName": "default",
			"policyName":    "test-policy",
		},
		Spec: tp.SecuritySpec{
			Selector: tp.SelectorType{
				Identities: []string{identity},
			},
		},
	}
}

// =========================================================
// Test 1: Core fix — profile cleanup on surviving endpoint
// =========================================================

func TestDestroyAppArmorCleanupOnSurvivingEndpoint(t *testing.T) {
	dm := newTestDaemon([]tp.SecurityPolicy{testPolicy("app=nginx")})

	container := tp.Container{
		ContainerID:     "cid-001",
		ContainerName:   "nginx",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_nginx",
		Labels:          "app=nginx",
	}

	if err := dm.UpdateContainer("cid-001", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// Verify profile registered
	dm.EndPointsLock.RLock()
	if len(dm.EndPoints) != 1 || len(dm.EndPoints[0].AppArmorProfiles) != 1 {
		dm.EndPointsLock.RUnlock()
		t.Fatalf("expected 1 endpoint with 1 AppArmor profile")
	}
	dm.EndPointsLock.RUnlock()

	if err := dm.UpdateContainer("cid-001", container, "destroy"); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}

	// Endpoint survives (has SecurityPolicy), profile must be cleaned
	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()
	if len(dm.EndPoints) != 1 {
		t.Fatalf("expected 1 endpoint to survive, got %d", len(dm.EndPoints))
	}
	if len(dm.EndPoints[0].AppArmorProfiles) != 0 {
		t.Errorf("AppArmor profile leaked: %v", dm.EndPoints[0].AppArmorProfiles)
	}
}

// =========================================================
// Test 2: Endpoint pruning when no policies and no containers
// =========================================================

func TestDestroyPrunesEndpointWithoutPolicies(t *testing.T) {
	dm := newTestDaemon(nil) // no SecurityPolicies

	container := tp.Container{
		ContainerID:     "cid-002",
		ContainerName:   "redis",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_redis",
		Labels:          "app=redis",
	}

	if err := dm.UpdateContainer("cid-002", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	if err := dm.UpdateContainer("cid-002", container, "destroy"); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}

	// No policies → endpoint should be fully pruned
	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()
	if len(dm.EndPoints) != 0 {
		t.Errorf("expected 0 endpoints after destroy (no policies), got %d", len(dm.EndPoints))
	}
}

// =========================================================
// Test 3: Destroy a non-existent container returns error
// =========================================================

func TestDestroyNonExistentContainerReturnsError(t *testing.T) {
	dm := newTestDaemon(nil)

	err := dm.UpdateContainer("does-not-exist", tp.Container{}, "destroy")
	if err == nil {
		t.Errorf("expected error destroying non-existent container, got nil")
	}
}

// =========================================================
// Test 4: Create duplicate container returns error
// =========================================================

func TestCreateDuplicateContainerReturnsError(t *testing.T) {
	dm := newTestDaemon(nil)

	container := tp.Container{
		ContainerID:     "cid-004",
		ContainerName:   "mongo",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_mongo",
		Labels:          "app=mongo",
	}

	if err := dm.UpdateContainer("cid-004", container, "create"); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	if err := dm.UpdateContainer("cid-004", container, "create"); err == nil {
		t.Errorf("expected error on duplicate create, got nil")
	}
}

// =========================================================
// Test 5: Create with empty container ID returns error
// =========================================================

func TestCreateEmptyContainerIDReturnsError(t *testing.T) {
	dm := newTestDaemon(nil)

	container := tp.Container{
		ContainerID:   "",
		ContainerName: "ghost",
	}

	err := dm.UpdateContainer("", container, "create")
	if err == nil {
		t.Errorf("expected error creating container with empty ID, got nil")
	}
}

// =========================================================
// Test 6: Container removed from dm.Containers map on destroy
// =========================================================

func TestDestroyRemovesContainerFromMap(t *testing.T) {
	dm := newTestDaemon(nil)

	container := tp.Container{
		ContainerID:     "cid-006",
		ContainerName:   "postgres",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_postgres",
		Labels:          "app=postgres",
	}

	if err := dm.UpdateContainer("cid-006", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	dm.ContainersLock.RLock()
	if _, ok := dm.Containers["cid-006"]; !ok {
		dm.ContainersLock.RUnlock()
		t.Fatalf("container not found in map after create")
	}
	dm.ContainersLock.RUnlock()

	if err := dm.UpdateContainer("cid-006", container, "destroy"); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}

	dm.ContainersLock.RLock()
	defer dm.ContainersLock.RUnlock()
	if _, ok := dm.Containers["cid-006"]; ok {
		t.Errorf("container still in map after destroy")
	}
}

// =========================================================
// Test 7: Destroy one of two containers — other's profile remains
// =========================================================

func TestDestroyOneOfTwoContainersPreservesOther(t *testing.T) {
	dm := newTestDaemon([]tp.SecurityPolicy{
		testPolicy("app=web"),
		testPolicy("app=worker"),
	})

	web := tp.Container{
		ContainerID:     "cid-web",
		ContainerName:   "web",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_web",
		Labels:          "app=web",
	}
	worker := tp.Container{
		ContainerID:     "cid-worker",
		ContainerName:   "worker",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_worker",
		Labels:          "app=worker",
	}

	if err := dm.UpdateContainer("cid-web", web, "create"); err != nil {
		t.Fatalf("create web failed: %v", err)
	}
	if err := dm.UpdateContainer("cid-worker", worker, "create"); err != nil {
		t.Fatalf("create worker failed: %v", err)
	}

	// Verify 2 endpoints exist
	dm.EndPointsLock.RLock()
	if len(dm.EndPoints) != 2 {
		dm.EndPointsLock.RUnlock()
		t.Fatalf("expected 2 endpoints, got %d", len(dm.EndPoints))
	}
	dm.EndPointsLock.RUnlock()

	// Destroy only web
	if err := dm.UpdateContainer("cid-web", web, "destroy"); err != nil {
		t.Fatalf("destroy web failed: %v", err)
	}

	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()

	// Web endpoint survives (has policy) but its profile must be cleaned
	// Worker endpoint must be untouched
	if len(dm.EndPoints) != 2 {
		t.Fatalf("expected 2 endpoints (both have policies), got %d", len(dm.EndPoints))
	}

	for _, ep := range dm.EndPoints {
		if ep.EndPointName == "web" {
			if len(ep.AppArmorProfiles) != 0 {
				t.Errorf("web AppArmor profile leaked: %v", ep.AppArmorProfiles)
			}
			if len(ep.Containers) != 0 {
				t.Errorf("web containers not cleaned: %v", ep.Containers)
			}
		}
		if ep.EndPointName == "worker" {
			if len(ep.AppArmorProfiles) != 1 || ep.AppArmorProfiles[0] != "kubearmor_worker" {
				t.Errorf("worker AppArmor profile missing or wrong: %v", ep.AppArmorProfiles)
			}
			if len(ep.Containers) != 1 || ep.Containers[0] != "cid-worker" {
				t.Errorf("worker container missing or wrong: %v", ep.Containers)
			}
		}
	}
}

// =========================================================
// Test 8: Container with empty AppArmorProfile — no panic
// =========================================================

func TestDestroyContainerWithEmptyAppArmorProfile(t *testing.T) {
	dm := newTestDaemon(nil)

	container := tp.Container{
		ContainerID:     "cid-008",
		ContainerName:   "bare",
		NamespaceName:   "default",
		AppArmorProfile: "",
		Labels:          "app=bare",
	}

	if err := dm.UpdateContainer("cid-008", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// Should not panic even with empty AppArmorProfile
	if err := dm.UpdateContainer("cid-008", container, "destroy"); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}
}

// =========================================================
// Test 9: Double destroy — second returns error
// =========================================================

func TestDoubleDestroyReturnsError(t *testing.T) {
	dm := newTestDaemon(nil)

	container := tp.Container{
		ContainerID:     "cid-009",
		ContainerName:   "temp",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_temp",
		Labels:          "app=temp",
	}

	if err := dm.UpdateContainer("cid-009", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if err := dm.UpdateContainer("cid-009", container, "destroy"); err != nil {
		t.Fatalf("first destroy failed: %v", err)
	}
	if err := dm.UpdateContainer("cid-009", container, "destroy"); err == nil {
		t.Errorf("expected error on double destroy, got nil")
	}
}

// =========================================================
// Test 10: Create-destroy-recreate lifecycle
// =========================================================

func TestCreateDestroyRecreateLifecycle(t *testing.T) {
	dm := newTestDaemon([]tp.SecurityPolicy{testPolicy("app=cycle")})

	container := tp.Container{
		ContainerID:     "cid-010",
		ContainerName:   "cycle",
		NamespaceName:   "default",
		AppArmorProfile: "kubearmor_cycle",
		Labels:          "app=cycle",
	}

	// Create
	if err := dm.UpdateContainer("cid-010", container, "create"); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// Destroy
	if err := dm.UpdateContainer("cid-010", container, "destroy"); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}

	// Verify profile cleaned on surviving endpoint
	dm.EndPointsLock.RLock()
	if len(dm.EndPoints) != 1 {
		dm.EndPointsLock.RUnlock()
		t.Fatalf("expected 1 endpoint after destroy, got %d", len(dm.EndPoints))
	}
	if len(dm.EndPoints[0].AppArmorProfiles) != 0 {
		dm.EndPointsLock.RUnlock()
		t.Fatalf("profile leaked after destroy: %v", dm.EndPoints[0].AppArmorProfiles)
	}
	dm.EndPointsLock.RUnlock()

	// Recreate with new container ID (simulates container restart)
	container2 := container
	container2.ContainerID = "cid-010-v2"

	if err := dm.UpdateContainer("cid-010-v2", container2, "create"); err != nil {
		t.Fatalf("recreate failed: %v", err)
	}

	// Should have 2 endpoints now (original surviving + new one)
	// New endpoint should have the profile
	dm.EndPointsLock.RLock()
	defer dm.EndPointsLock.RUnlock()

	foundNewProfile := false
	for _, ep := range dm.EndPoints {
		if len(ep.Containers) == 1 && ep.Containers[0] == "cid-010-v2" {
			if len(ep.AppArmorProfiles) == 1 && ep.AppArmorProfiles[0] == "kubearmor_cycle" {
				foundNewProfile = true
			}
		}
	}
	if !foundNewProfile {
		t.Errorf("recreated container did not get AppArmor profile")
	}
}
