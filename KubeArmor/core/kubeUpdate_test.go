// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testNode(machineID string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node-a",
			Labels: map[string]string{"kubearmor.io/enforcer": "bpf"},
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{MachineID: machineID},
		},
	}
}

func TestCheckAndUpdateNodeMachineID(t *testing.T) {
	dm := &KubeArmorDaemon{NodeLock: &sync.RWMutex{}}

	dm.checkAndUpdateNode(testNode("0123456789abcdef0123456789abcdef"))
	if dm.Node.NodeID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("NodeID = %q, want the node's MachineID", dm.Node.NodeID)
	}

	// an update without a MachineID must not clear the known ID
	dm.checkAndUpdateNode(testNode(""))
	if dm.Node.NodeID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("NodeID = %q after update without MachineID, want it preserved", dm.Node.NodeID)
	}
}

func TestCheckAndUpdateNodeKeepsStartupNodeID(t *testing.T) {
	dm := &KubeArmorDaemon{
		NodeLock: &sync.RWMutex{},
		Node:     tp.Node{NodeID: "node-a"},
	}

	dm.checkAndUpdateNode(testNode(""))
	if dm.Node.NodeID != "node-a" {
		t.Fatalf("NodeID = %q, want the startup value kept", dm.Node.NodeID)
	}
}
