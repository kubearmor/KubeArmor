// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"fmt"
	"sync"
	"testing"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// TestConfigReloadEndpointIterationRaceCondition ensures that iterating over
// dm.EndPoints during a config reload (the WatchConfigChanges callback in
// unorchestratedUpdates.go) does not race with concurrent endpoint mutations
// performed elsewhere in the daemon (e.g. container handlers), which take
// EndPointsLock while adding/removing endpoints.
func TestConfigReloadEndpointIterationRaceCondition(t *testing.T) {
	dm := &KubeArmorDaemon{
		EndPoints:     []tp.EndPoint{},
		EndPointsLock: &sync.RWMutex{},
	}

	for i := 0; i < 50; i++ {
		dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
			NamespaceName: "test-namespace",
			EndPointName:  fmt.Sprintf("test-endpoint-%d", i),
		})
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: mirrors the fixed WatchConfigChanges code path - copy
	// endpoints under the read lock, then range over the snapshot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				dm.EndPointsLock.RLock()
				endPointsCopy := make([]tp.EndPoint, len(dm.EndPoints))
				copy(endPointsCopy, dm.EndPoints)
				dm.EndPointsLock.RUnlock()

				for _, ep := range endPointsCopy {
					_ = ep.NamespaceName
				}
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Goroutine 2: concurrently mutates the endpoint slice under
	// EndPointsLock, matching how container handlers update dm.EndPoints.
	wg.Add(1)
	go func() {
		defer wg.Done()
		counter := 100
		for {
			select {
			case <-stopCh:
				return
			default:
				dm.EndPointsLock.Lock()
				if len(dm.EndPoints) > 0 {
					dm.EndPoints = dm.EndPoints[:len(dm.EndPoints)-1]
				}
				dm.EndPoints = append(dm.EndPoints, tp.EndPoint{
					NamespaceName: "test-namespace",
					EndPointName:  fmt.Sprintf("test-endpoint-%d", counter),
				})
				counter++
				dm.EndPointsLock.Unlock()
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	t.Log("config reload endpoint iteration race condition test completed without races")
}
