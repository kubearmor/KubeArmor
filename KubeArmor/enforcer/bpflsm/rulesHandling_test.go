package bpflsm

import (
	"sync"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestUpdateContainerRulesNilMap(t *testing.T) {
	// Initialize a dummy Feeder logger
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)
	logger := feeder.NewFeeder(&node, &nodeLock)

	// Initialize the enforcer with only the necessary fields
	be := &BPFEnforcer{
		Logger:           logger,
		ContainerMap:     make(map[string]ContainerKV),
		ContainerMapLock: new(sync.RWMutex),
	}

	containerID := "test-container-id"
	
	// Add container to the map but purposefully do NOT initialize its InnerMap
	// This simulates a scenario where CreateContainerInnerMap fails due to eBPF limits
	var rules RuleList
	rules.Init()
	be.ContainerMap[containerID] = ContainerKV{
		Key:   NsKey{PidNS: 1234, MntNS: 5678},
		Map:   nil, // explicitly nil map
		Rules: rules,
	}

	// Create a dummy policy that triggers map creation/updates
	policies := []tp.SecurityPolicy{
		{
			Spec: tp.SecuritySpec{
				Process: tp.ProcessType{
					MatchPaths: []tp.ProcessPathType{
						{
							Path:   "/bin/bash",
							Action: "Block",
						},
					},
				},
			},
		},
	}

	defaultPosture := tp.DefaultPosture{
		FileAction:         "Audit",
		NetworkAction:      "Audit",
		CapabilitiesAction: "Audit",
	}

	// Run UpdateContainerRules and catch any panics
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UpdateContainerRules panicked when inner map was nil: %v", r)
		}
	}()

	// This function call should safely abort without a panic due to the nil map check
	be.UpdateContainerRules(containerID, policies, defaultPosture)

	// Verify that the map is still nil and the enforcer didn't crash
	if be.ContainerMap[containerID].Map != nil {
		t.Errorf("Expected ContainerMap.Map to remain nil")
	}
}
