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

func TestConfigReloadEndpointIterationRaceCondition(t *testing.T) {
	t.Parallel()

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

				for _, namespace := range uniqueEndpointNamespaces(endPointsCopy) {
					_ = namespace
				}

				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

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
}
