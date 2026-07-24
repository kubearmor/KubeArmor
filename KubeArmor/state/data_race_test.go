// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package state

import (
	"fmt"
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func newTestStateAgent() *StateAgent {
	node := &tp.Node{NodeName: "test-node"}
	return NewStateAgent(node, new(sync.RWMutex), map[string]tp.Container{}, new(sync.RWMutex))
}

// TestPushContainerEventRace demonstrates the unsynchronized read of
// sa.StateEventChans in PushContainerEvent racing with clients
// connecting/disconnecting (addStateEventChan/removeStateEventChan).
// Run with -race to observe the data race.
func TestPushContainerEventRace(t *testing.T) {
	sa := newTestStateAgent()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// simulate WatchState clients connecting and disconnecting
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			uid, conn := sa.addStateEventChan()
			// drain a bit like WatchState would
			select {
			case <-conn:
			default:
			}
			sa.removeStateEventChan(uid)
		}
	}()

	// simulate container events pushed by the runtime handlers
	// (containerdHandler/dockerHandler call these via `go ...`)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			sa.PushContainerEvent(tp.Container{
				ContainerID:   fmt.Sprintf("c%d", i),
				ContainerName: "nginx",
				NamespaceName: "default",
			}, EventAdded)
		}
		close(stop)
	}()

	wg.Wait()
}
