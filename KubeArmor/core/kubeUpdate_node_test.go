// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	corev1 "k8s.io/api/core/v1"
)

func TestCheckAndUpdateNodeID(t *testing.T) {
	tests := []struct {
		name      string
		previous  string
		machineID string
		want      string
	}{
		{"uses kubelet machine id", "node-a", "0123456789abcdef", "0123456789abcdef"},
		{"keeps previous id when machine id is empty", "fedcba9876543210", "", "fedcba9876543210"},
		{"empty when nothing is known", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &KubeArmorDaemon{
				Node:     tp.Node{NodeID: tt.previous},
				NodeLock: &sync.RWMutex{},
			}

			item := &corev1.Node{
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
					NodeInfo:  corev1.NodeSystemInfo{MachineID: tt.machineID, KernelVersion: "6.8.0"},
				},
			}

			dm.checkAndUpdateNode(item)

			if dm.Node.NodeID != tt.want {
				t.Errorf("NodeID = %q, want %q", dm.Node.NodeID, tt.want)
			}
			if dm.Node.NodeIP != "10.0.0.1" || dm.Node.KernelVersion != "6.8.0" {
				t.Errorf("node info not refreshed: ip=%q kernel=%q", dm.Node.NodeIP, dm.Node.KernelVersion)
			}
		})
	}
}

// node updates arrive repeatedly; the id must survive every one of them
func TestCheckAndUpdateNodeKeepsIDAcrossUpdates(t *testing.T) {
	dm := &KubeArmorDaemon{NodeLock: &sync.RWMutex{}}

	item := &corev1.Node{Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{MachineID: "0123456789abcdef"}}}
	dm.checkAndUpdateNode(item)

	item.Status.NodeInfo.MachineID = ""
	for range 3 {
		dm.checkAndUpdateNode(item)
	}

	if dm.Node.NodeID != "0123456789abcdef" {
		t.Errorf("NodeID = %q after updates, want %q", dm.Node.NodeID, "0123456789abcdef")
	}
}
