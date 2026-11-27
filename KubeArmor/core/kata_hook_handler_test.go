// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func newTestKataDaemon(t *testing.T, k8sEnabled bool) *KubeArmorDaemon {
	t.Helper()

	dm := &KubeArmorDaemon{
		K8sEnabled:                  k8sEnabled,
		Node:                        tp.Node{NodeName: "test-node"},
		NodeLock:                    new(sync.RWMutex),
		Containers:                  make(map[string]tp.Container),
		ContainersLock:              new(sync.RWMutex),
		EndPoints:                   []tp.EndPoint{},
		EndPointsLock:               new(sync.RWMutex),
		OwnerInfo:                   make(map[string]tp.PodOwner),
		OwnerInfoLock:               new(sync.RWMutex),
		SecurityPolicies:            []tp.SecurityPolicy{},
		SecurityPoliciesLock:        new(sync.RWMutex),
		HostSecurityPolicies:        []tp.HostSecurityPolicy{},
		HostSecurityPoliciesLock:    new(sync.RWMutex),
		NetworkSecurityPolicies:     []tp.NetworkSecurityPolicy{},
		NetworkSecurityPoliciesLock: new(sync.RWMutex),
		DefaultPostures:             make(map[string]tp.DefaultPosture),
		DefaultPosturesLock:         new(sync.Mutex),
	}

	dm.Logger = &fd.Feeder{
		BaseFeeder: fd.BaseFeeder{
			Node:         &dm.Node,
			NodeLock:     &dm.NodeLock,
			Enforcer:     "eBPF Monitor",
			EnforcerLock: new(sync.RWMutex),
			EventStructs: &fd.EventStructs{
				MsgStructs:   make(map[string]fd.EventStruct[pb.Message]),
				AlertStructs: make(map[string]fd.EventStruct[pb.Alert]),
				LogStructs:   make(map[string]fd.EventStruct[pb.Log]),
			},
		},
		SecurityPolicies:     make(map[string]tp.MatchPolicies),
		SecurityPoliciesLock: new(sync.RWMutex),
		DefaultPostures:      make(map[string]tp.DefaultPosture),
		DefaultPosturesLock:  new(sync.RWMutex),
		AlertMap:             make(map[fd.OuterKey]fd.AlertThrottleState),
		ContainerNsKey:       make(map[string]kl.OuterKey),
	}

	return dm
}

func saveAndResetStopChan(t *testing.T) chan struct{} {
	t.Helper()
	orig := StopChan
	ch := make(chan struct{})
	StopChan = ch
	t.Cleanup(func() {
		StopChan = orig
	})
	return ch
}

func overrideKataHookWaitTimings(t *testing.T, timeout, poll time.Duration) {
	t.Helper()
	origTimeout := kataHookWaitTimeout
	origPoll := kataHookPollInterval
	kataHookWaitTimeout = timeout
	kataHookPollInterval = poll
	t.Cleanup(func() {
		kataHookWaitTimeout = origTimeout
		kataHookPollInterval = origPoll
	})
}

func atomicWriteHookJSON(t *testing.T, target string, snapshot map[string]tp.Container) {
	t.Helper()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".hook-test-*.tmp")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		t.Fatalf("failed to rename temp file: %v", err)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func TestHandleContainerCreateForKata_InvalidInputsSkipped(t *testing.T) {
	tests := []struct {
		name      string
		container tp.Container
	}{
		{
			name:      "empty container ID with valid namespaces",
			container: tp.Container{ContainerID: "", PidNS: 100, MntNS: 200},
		},
		{
			name:      "zero PidNS and zero MntNS",
			container: tp.Container{ContainerID: "c1", PidNS: 0, MntNS: 0},
		},
		{
			name:      "partial namespace PidNS only",
			container: tp.Container{ContainerID: "c1", PidNS: 123, MntNS: 0},
		},
		{
			name:      "partial namespace MntNS only",
			container: tp.Container{ContainerID: "c1", PidNS: 0, MntNS: 456},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dm := newTestKataDaemon(t, true)
			if created := dm.HandleContainerCreateForKata(tc.container); created {
				t.Fatalf("expected HandleContainerCreateForKata to return false for %s", tc.name)
			}
			if len(dm.Containers) != 0 {
				t.Fatalf("expected dm.Containers to remain empty, got %d", len(dm.Containers))
			}
			if len(dm.EndPoints) != 0 {
				t.Fatalf("expected dm.EndPoints to remain empty, got %d", len(dm.EndPoints))
			}
		})
	}
}

func TestHandleContainerCreateForKata_AppArmorSanitization(t *testing.T) {
	badProfiles := []string{"../etc/passwd", "foo/bar", `foo\bar`}

	for _, k8sEnabled := range []bool{false, true} {
		mode := "non-k8s"
		if k8sEnabled {
			mode = "k8s"
		}
		for _, bad := range badProfiles {
			t.Run(mode+"_new_"+bad, func(t *testing.T) {
				dm := newTestKataDaemon(t, k8sEnabled)
				ok := dm.HandleContainerCreateForKata(tp.Container{
					ContainerID:     "cid-new",
					ContainerName:   "nginx",
					NamespaceName:   "default",
					AppArmorProfile: bad,
					PidNS:           1001,
					MntNS:           2001,
				})
				if !ok {
					t.Fatalf("expected create to succeed")
				}
				if got := dm.Containers["cid-new"].AppArmorProfile; got != "" {
					t.Fatalf("expected invalid profile %q to be stripped, got %q", bad, got)
				}
			})
		}
	}

	for _, bad := range badProfiles {
		t.Run("existing_pod_informer_"+bad, func(t *testing.T) {
			dm := newTestKataDaemon(t, true)
			dm.Containers["cid-exist"] = tp.Container{
				ContainerID:   "cid-exist",
				ContainerName: "nginx",
				NamespaceName: "default",
				EndPointName:  "web-pod",
				PidNS:         0,
				MntNS:         0,
			}
			dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
				NamespaceName:    "default",
				EndPointName:     "web-pod",
				Containers:       []string{"cid-exist"},
				AppArmorProfiles: []string{},
			})

			ok := dm.HandleContainerCreateForKata(tp.Container{
				ContainerID:     "cid-exist",
				AppArmorProfile: bad,
				PidNS:           1002,
				MntNS:           2002,
			})
			if !ok {
				t.Fatalf("expected update to succeed")
			}
			if got := dm.Containers["cid-exist"].AppArmorProfile; got != "" {
				t.Fatalf("expected existing.AppArmorProfile to remain empty, got %q", got)
			}
			if len(dm.EndPoints[0].AppArmorProfiles) != 0 {
				t.Fatalf("expected endpoint.AppArmorProfiles to remain empty, got %v", dm.EndPoints[0].AppArmorProfiles)
			}
		})
	}

	t.Run("valid_profile_preserved_and_deduplicated", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		dm.Containers["cid-valid"] = tp.Container{
			ContainerID:     "cid-valid",
			ContainerName:   "nginx",
			NamespaceName:   "default",
			EndPointName:    "web-pod",
			AppArmorProfile: "kubearmor_nginx",
			PidNS:           0,
			MntNS:           0,
		}
		dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
			NamespaceName:    "default",
			EndPointName:     "web-pod",
			Containers:       []string{"cid-valid"},
			AppArmorProfiles: []string{"kubearmor_nginx"},
		})

		ok := dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:     "cid-valid",
			AppArmorProfile: "kubearmor_nginx",
			PidNS:           1003,
			MntNS:           2003,
		})
		if !ok {
			t.Fatalf("expected update to succeed")
		}
		if got := dm.Containers["cid-valid"].AppArmorProfile; got != "kubearmor_nginx" {
			t.Fatalf("expected profile kubearmor_nginx, got %q", got)
		}
		if len(dm.EndPoints[0].AppArmorProfiles) != 1 || dm.EndPoints[0].AppArmorProfiles[0] != "kubearmor_nginx" {
			t.Fatalf("expected single kubearmor_nginx entry, got %v", dm.EndPoints[0].AppArmorProfiles)
		}
	})
}

func TestHandleContainerCreateForKata_ModesAndLifecycle(t *testing.T) {
	t.Run("non-k8s create populates namespace, labels, and endpoint", func(t *testing.T) {
		dm := newTestKataDaemon(t, false)
		ok := dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-nonk8s",
			ContainerName: "nginx",
			PidNS:         111,
			MntNS:         222,
		})
		if !ok {
			t.Fatalf("expected true")
		}
		c, exists := dm.Containers["cid-nonk8s"]
		if !exists {
			t.Fatalf("expected container stored in dm.Containers")
		}
		if c.NamespaceName != "container_namespace" {
			t.Fatalf("expected NamespaceName=container_namespace, got %q", c.NamespaceName)
		}
		wantLabels := "namespaceName=container_namespace,kubearmor.io/container.name=nginx"
		if c.Labels != wantLabels {
			t.Fatalf("expected Labels=%q, got %q", wantLabels, c.Labels)
		}
		if len(dm.EndPoints) != 1 {
			t.Fatalf("expected 1 endpoint created, got %d", len(dm.EndPoints))
		}
		if dm.EndPoints[0].EndPointName != "nginx" || !kl.ContainsElement(dm.EndPoints[0].Containers, "cid-nonk8s") {
			t.Fatalf("unexpected endpoint created: %+v", dm.EndPoints[0])
		}
	})

	t.Run("k8s create before pod informer defaults empty namespace to Unknown", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		ok := dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-early",
			ContainerName: "app",
			NamespaceName: "",
			PidNS:         333,
			MntNS:         444,
		})
		if !ok {
			t.Fatalf("expected true")
		}
		if got := dm.Containers["cid-early"].NamespaceName; got != "Unknown" {
			t.Fatalf("expected NamespaceName=Unknown, got %q", got)
		}
		if len(dm.EndPoints) != 0 {
			t.Fatalf("expected no endpoint created in K8s mode before Pod informer, got %d", len(dm.EndPoints))
		}
	})

	t.Run("k8s update after pod informer updates namespaces and endpoint profile", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		dm.Containers["cid-pod"] = tp.Container{
			ContainerID:   "cid-pod",
			ContainerName: "nginx",
			NamespaceName: "prod",
			EndPointName:  "nginx-pod",
			PidNS:         0,
			MntNS:         0,
		}
		dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
			NamespaceName:    "prod",
			EndPointName:     "nginx-pod",
			Containers:       []string{"cid-pod"},
			AppArmorProfiles: []string{},
		})

		ok := dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:     "cid-pod",
			AppArmorProfile: "kubearmor_nginx",
			PidNS:           555,
			MntNS:           666,
		})
		if !ok {
			t.Fatalf("expected true")
		}
		got := dm.Containers["cid-pod"]
		if got.PidNS != 555 || got.MntNS != 666 || got.AppArmorProfile != "kubearmor_nginx" {
			t.Fatalf("unexpected updated container: %+v", got)
		}
		if !kl.ContainsElement(dm.EndPoints[0].AppArmorProfiles, "kubearmor_nginx") {
			t.Fatalf("expected AppArmorProfile added to endpoint, got %v", dm.EndPoints[0].AppArmorProfiles)
		}
	})

	t.Run("duplicate snapshot ignored when namespaces already resolved", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-dup",
			ContainerName: "orig-name",
			NamespaceName: "orig-ns",
			PidNS:         777,
			MntNS:         888,
		})

		ok := dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-dup",
			ContainerName: "new-name",
			NamespaceName: "new-ns",
			PidNS:         999,
			MntNS:         1111,
		})
		if ok {
			t.Fatalf("expected duplicate create to return false")
		}
		got := dm.Containers["cid-dup"]
		if got.ContainerName != "orig-name" || got.NamespaceName != "orig-ns" || got.PidNS != 777 || got.MntNS != 888 {
			t.Fatalf("expected existing container metadata to remain unchanged, got %+v", got)
		}
	})
}

func TestHandleContainerDeleteForKata(t *testing.T) {
	t.Run("missing container ID is a safe no-op", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		dm.HandleContainerDeleteForKata("does-not-exist")
	})

	t.Run("non-k8s delete removes empty endpoint", func(t *testing.T) {
		dm := newTestKataDaemon(t, false)
		dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-1",
			ContainerName: "c1",
			PidNS:         100,
			MntNS:         200,
		})
		if len(dm.EndPoints) != 1 {
			t.Fatalf("expected 1 endpoint before delete, got %d", len(dm.EndPoints))
		}

		dm.HandleContainerDeleteForKata("cid-1")
		if _, exists := dm.Containers["cid-1"]; exists {
			t.Fatalf("expected cid-1 removed from dm.Containers")
		}
		if len(dm.EndPoints) != 0 {
			t.Fatalf("expected empty endpoint to be deleted, got %d", len(dm.EndPoints))
		}
	})

	t.Run("non-k8s delete retains policy-bearing endpoint", func(t *testing.T) {
		dm := newTestKataDaemon(t, false)
		dm.HandleContainerCreateForKata(tp.Container{
			ContainerID:   "cid-pol",
			ContainerName: "c1",
			PidNS:         100,
			MntNS:         200,
		})
		dm.EndPoints[0].SecurityPolicies = []tp.SecurityPolicy{
			{Metadata: map[string]string{"policyName": "keep-me"}},
		}

		dm.HandleContainerDeleteForKata("cid-pol")
		if _, exists := dm.Containers["cid-pol"]; exists {
			t.Fatalf("expected cid-pol removed from dm.Containers")
		}
		if len(dm.EndPoints) != 1 {
			t.Fatalf("expected policy-bearing endpoint to remain, got %d", len(dm.EndPoints))
		}
		if len(dm.EndPoints[0].Containers) != 0 {
			t.Fatalf("expected container removed from endpoint.Containers, got %v", dm.EndPoints[0].Containers)
		}
	})

	t.Run("k8s delete cleans profile and leaves other endpoints untouched", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		dm.Containers["cid-a"] = tp.Container{
			ContainerID:     "cid-a",
			NamespaceName:   "ns1",
			EndPointName:    "pod-a",
			AppArmorProfile: "prof-a",
			PidNS:           10,
			MntNS:           20,
		}
		dm.Containers["cid-b"] = tp.Container{
			ContainerID:     "cid-b",
			NamespaceName:   "ns1",
			EndPointName:    "pod-b",
			AppArmorProfile: "prof-b",
			PidNS:           30,
			MntNS:           40,
		}
		dm.EndPoints = []tp.EndPoint{
			{
				NamespaceName:    "ns1",
				EndPointName:     "pod-a",
				Containers:       []string{"cid-a"},
				AppArmorProfiles: []string{"prof-a", "prof-other"},
			},
			{
				NamespaceName:    "ns1",
				EndPointName:     "pod-b",
				Containers:       []string{"cid-b"},
				AppArmorProfiles: []string{"prof-b"},
			},
		}

		dm.HandleContainerDeleteForKata("cid-a")
		if _, exists := dm.Containers["cid-a"]; exists {
			t.Fatalf("expected cid-a deleted")
		}
		if _, exists := dm.Containers["cid-b"]; !exists {
			t.Fatalf("expected cid-b untouched")
		}
		if len(dm.EndPoints[0].AppArmorProfiles) != 1 || dm.EndPoints[0].AppArmorProfiles[0] != "prof-other" {
			t.Fatalf("expected prof-a removed from pod-a, got %v", dm.EndPoints[0].AppArmorProfiles)
		}
		if len(dm.EndPoints[1].AppArmorProfiles) != 1 || dm.EndPoints[1].AppArmorProfiles[0] != "prof-b" {
			t.Fatalf("expected pod-b profiles untouched, got %v", dm.EndPoints[1].AppArmorProfiles)
		}
	})

	t.Run("missing ContainerNsKey does not delete zero key from AlertMap", func(t *testing.T) {
		origPolicy := cfg.GlobalCfg.Policy
		cfg.GlobalCfg.Policy = true
		t.Cleanup(func() {
			cfg.GlobalCfg.Policy = origPolicy
		})

		dm := newTestKataDaemon(t, true)
		dm.SystemMonitor = &mon.SystemMonitor{
			Logger:           dm.Logger,
			NsMap:            make(map[mon.NsKey]string),
			NsMapLock:        new(sync.RWMutex),
			NamespacePidsMap: make(map[string]mon.NsVisibility),
			BpfMapLock:       new(sync.RWMutex),
		}

		zeroKey := fd.OuterKey{PidNs: 0, MntNs: 0}
		dm.Logger.AlertMap[zeroKey] = fd.AlertThrottleState{EventCount: 99}
		dm.Containers["cid-no-nskey"] = tp.Container{
			ContainerID:   "cid-no-nskey",
			NamespaceName: "default",
			PidNS:         11,
			MntNS:         22,
		}

		dm.HandleContainerDeleteForKata("cid-no-nskey")
		if state, ok := dm.Logger.AlertMap[zeroKey]; !ok || state.EventCount != 99 {
			t.Fatalf("expected zero OuterKey to stay in AlertMap, got present=%v state=%+v", ok, state)
		}
	})
}

func TestProcessKataHookFile(t *testing.T) {
	t.Run("empty or whitespace-only file preserves active containers", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")

		dm.Containers["c1"] = tp.Container{ContainerID: "c1", PidNS: 10, MntNS: 20}
		active := map[string]struct{}{"c1": {}}

		for _, content := range []string{"", "   \n\t  "} {
			if err := os.WriteFile(hookFile, []byte(content), 0600); err != nil {
				t.Fatalf("write failed: %v", err)
			}
			if err := dm.processKataHookFile(hookFile, active); err != nil {
				t.Fatalf("expected nil error for %q, got %v", content, err)
			}
			if _, ok := dm.Containers["c1"]; !ok {
				t.Fatalf("expected c1 preserved in dm.Containers for content %q", content)
			}
			if _, ok := active["c1"]; !ok {
				t.Fatalf("expected c1 preserved in activeContainers for content %q", content)
			}
		}
	})

	t.Run("explicit empty object clears everything", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		dm.Containers["c1"] = tp.Container{ContainerID: "c1", PidNS: 10, MntNS: 20}
		active := map[string]struct{}{"c1": {}}

		if err := os.WriteFile(hookFile, []byte("{}"), 0600); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(dm.Containers) != 0 || len(active) != 0 {
			t.Fatalf("expected both maps empty, got containers=%d active=%d", len(dm.Containers), len(active))
		}
	})

	t.Run("malformed JSON returns error and leaves state intact", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		dm.Containers["c1"] = tp.Container{ContainerID: "c1", PidNS: 10, MntNS: 20}
		active := map[string]struct{}{"c1": {}}

		if err := os.WriteFile(hookFile, []byte("{bad json"), 0600); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := dm.processKataHookFile(hookFile, active); err == nil {
			t.Fatalf("expected error for malformed JSON")
		}
		if _, ok := dm.Containers["c1"]; !ok {
			t.Fatalf("expected c1 intact in dm.Containers")
		}
		if _, ok := active["c1"]; !ok {
			t.Fatalf("expected c1 intact in activeContainers")
		}
	})

	t.Run("skipped invalid container is never tracked or deleted", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		dm.Containers["c_pending"] = tp.Container{ContainerID: "c_pending", PidNS: 0, MntNS: 0}
		active := map[string]struct{}{}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c_pending": {ContainerID: "c_pending", PidNS: 0, MntNS: 0},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 1 failed: %v", err)
		}
		if _, tracked := active["c_pending"]; tracked {
			t.Fatalf("c_pending with PidNS=0 should not be tracked")
		}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 2 failed: %v", err)
		}
		if _, ok := dm.Containers["c_pending"]; !ok {
			t.Fatalf("expected Pod-informer c_pending entry to remain untouched in dm.Containers")
		}
	})

	t.Run("map key vs ContainerID normalization", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		active := map[string]struct{}{}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"key-only": {ContainerID: "", PidNS: 11, MntNS: 12},
			"short-id": {ContainerID: "full-id", PidNS: 21, MntNS: 22},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 1 failed: %v", err)
		}
		if _, ok := dm.Containers["key-only"]; !ok {
			t.Fatalf("expected key-only registered")
		}
		if _, ok := dm.Containers["full-id"]; !ok {
			t.Fatalf("expected full-id registered")
		}
		if _, ok := dm.Containers["short-id"]; ok {
			t.Fatalf("did not expect short-id key in dm.Containers")
		}
		if _, ok := active["full-id"]; !ok {
			t.Fatalf("expected full-id tracked in activeContainers")
		}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 2 failed: %v", err)
		}
		if len(dm.Containers) != 0 || len(active) != 0 {
			t.Fatalf("expected all normalized containers removed, got containers=%v active=%v", dm.Containers, active)
		}
	})

	t.Run("already-tracked IDs are not re-processed", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		active := map[string]struct{}{}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", ContainerName: "orig", PidNS: 101, MntNS: 201},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 1 failed: %v", err)
		}

		// Mutate stored container locally; a snapshot still containing c1 must not overwrite it.
		mutated := dm.Containers["c1"]
		mutated.ContainerName = "mutated-sentinel"
		dm.Containers["c1"] = mutated

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", ContainerName: "from-hook", PidNS: 101, MntNS: 201},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("snapshot 2 failed: %v", err)
		}
		if got := dm.Containers["c1"].ContainerName; got != "mutated-sentinel" {
			t.Fatalf("expected mutation to persist, got %q", got)
		}
	})

	t.Run("multi-snapshot lifecycle", func(t *testing.T) {
		dm := newTestKataDaemon(t, true)
		hookFile := filepath.Join(t.TempDir(), "hook.json")
		active := map[string]struct{}{}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", PidNS: 1, MntNS: 2},
			"c2": {ContainerID: "c2", PidNS: 3, MntNS: 4},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("step 1 failed: %v", err)
		}
		if len(dm.Containers) != 2 {
			t.Fatalf("expected 2 containers, got %d", len(dm.Containers))
		}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", PidNS: 1, MntNS: 2},
			"c3": {ContainerID: "c3", PidNS: 5, MntNS: 6},
		})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("step 2 failed: %v", err)
		}
		if _, ok := dm.Containers["c2"]; ok {
			t.Fatalf("expected c2 deleted")
		}
		if _, ok := dm.Containers["c1"]; !ok {
			t.Fatalf("expected c1 retained")
		}
		if _, ok := dm.Containers["c3"]; !ok {
			t.Fatalf("expected c3 added")
		}

		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{})
		if err := dm.processKataHookFile(hookFile, active); err != nil {
			t.Fatalf("step 3 failed: %v", err)
		}
		if len(dm.Containers) != 0 || len(active) != 0 {
			t.Fatalf("expected clean state, got containers=%d active=%d", len(dm.Containers), len(active))
		}
	})
}

func TestWatchKataHookFile(t *testing.T) {
	t.Run("empty or whitespace path exits immediately", func(t *testing.T) {
		saveAndResetStopChan(t)
		dm := newTestKataDaemon(t, true)

		done := make(chan struct{})
		go func() {
			dm.WatchKataHookFile("   ")
			dm.WgDaemon.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("WatchKataHookFile did not exit immediately on empty path")
		}
	})

	t.Run("timeout without creating missing parent directories", func(t *testing.T) {
		saveAndResetStopChan(t)
		overrideKataHookWaitTimings(t, 150*time.Millisecond, 10*time.Millisecond)
		dm := newTestKataDaemon(t, true)

		missingDir := filepath.Join(t.TempDir(), "missing-dir")
		hookFile := filepath.Join(missingDir, "hook.json")

		start := time.Now()
		dm.WatchKataHookFile(hookFile)
		elapsed := time.Since(start)
		dm.WgDaemon.Wait()

		if elapsed < 120*time.Millisecond {
			t.Fatalf("expected wait close to 150ms, exited too early in %v", elapsed)
		}
		if _, err := os.Stat(missingDir); !os.IsNotExist(err) {
			t.Fatalf("expected %s NOT to be created, stat err=%v", missingDir, err)
		}
	})

	t.Run("delayed creation and atomic rename updates", func(t *testing.T) {
		stopCh := saveAndResetStopChan(t)
		overrideKataHookWaitTimings(t, 500*time.Millisecond, 10*time.Millisecond)
		dm := newTestKataDaemon(t, true)

		hookFile := filepath.Join(t.TempDir(), "hook.json")
		go dm.WatchKataHookFile(hookFile)

		time.Sleep(30 * time.Millisecond)
		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", PidNS: 101, MntNS: 201},
		})
		waitForCondition(t, time.Second, func() bool {
			dm.ContainersLock.RLock()
			defer dm.ContainersLock.RUnlock()
			_, ok := dm.Containers["c1"]
			return ok
		}, "c1 created")

		// Atomic rename replaces file inode with {c1, c2}
		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c1": {ContainerID: "c1", PidNS: 101, MntNS: 201},
			"c2": {ContainerID: "c2", PidNS: 102, MntNS: 202},
		})
		waitForCondition(t, time.Second, func() bool {
			dm.ContainersLock.RLock()
			defer dm.ContainersLock.RUnlock()
			_, ok := dm.Containers["c2"]
			return ok
		}, "c2 created after atomic rename")

		// Atomic rename removes c1 while keeping c2
		atomicWriteHookJSON(t, hookFile, map[string]tp.Container{
			"c2": {ContainerID: "c2", PidNS: 102, MntNS: 202},
		})
		waitForCondition(t, time.Second, func() bool {
			dm.ContainersLock.RLock()
			defer dm.ContainersLock.RUnlock()
			_, hasC1 := dm.Containers["c1"]
			_, hasC2 := dm.Containers["c2"]
			return !hasC1 && hasC2
		}, "c1 deleted while c2 stays")

		close(stopCh)
		done := make(chan struct{})
		go func() {
			dm.WgDaemon.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("WgDaemon.Wait() did not finish after StopChan close")
		}
	})

	t.Run("cancellation during startup wait exits promptly", func(t *testing.T) {
		stopCh := saveAndResetStopChan(t)
		overrideKataHookWaitTimings(t, 2*time.Second, 10*time.Millisecond)
		dm := newTestKataDaemon(t, true)

		hookFile := filepath.Join(t.TempDir(), "never-created.json")
		done := make(chan struct{})
		start := time.Now()
		go func() {
			dm.WatchKataHookFile(hookFile)
			dm.WgDaemon.Wait()
			close(done)
		}()

		time.Sleep(20 * time.Millisecond)
		close(stopCh)

		select {
		case <-done:
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("expected prompt cancellation, took %v", elapsed)
			}
		case <-time.After(time.Second):
			t.Fatalf("WatchKataHookFile did not exit on StopChan close")
		}
	})
}
