// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// TestUpdateSecurityPolicyRaceCondition tests that UpdateSecurityPolicy doesn't panic
// when endpoints are concurrently added/removed during policy updates
func TestUpdateSecurityPolicyRaceCondition(t *testing.T) {
	// Create a test daemon
	dm := &KubeArmorDaemon{
		EndPoints:                []tp.EndPoint{},
		EndPointsLock:            &sync.RWMutex{},
		SecurityPolicies:         []tp.SecurityPolicy{},
		SecurityPoliciesLock:     &sync.RWMutex{},
		HostSecurityPolicies:     []tp.HostSecurityPolicy{},
		HostSecurityPoliciesLock: &sync.RWMutex{},
		DefaultPostures:          map[string]tp.DefaultPosture{},
		DefaultPosturesLock:      &sync.Mutex{},
	}

	// Initialize with some test endpoints
	for i := 0; i < 50; i++ {
		endpoint := tp.EndPoint{
			NamespaceName:    "test-namespace",
			EndPointName:     fmt.Sprintf("test-endpoint-%d", i),
			ContainerName:    fmt.Sprintf("test-container-%d", i),
			Identities:       []string{fmt.Sprintf("label=value-%d", i)},
			SecurityPolicies: []tp.SecurityPolicy{},
		}
		dm.EndPoints = append(dm.EndPoints, endpoint)
	}

	// Test security policy
	testPolicy := tp.SecurityPolicy{
		Metadata: map[string]string{
			"namespaceName": "test-namespace",
			"policyName":    "test-policy",
		},
		Spec: tp.SecuritySpec{
			Selector: tp.SelectorType{
				Identities: []string{"label=value-1"},
			},
		},
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: Constantly update security policies
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				// This should not panic even if endpoints array changes
				dm.UpdateSecurityPolicy("add", "KubeArmorPolicy", testPolicy)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Goroutine 2: Constantly add/remove endpoints
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
					// Remove an endpoint
					// dm.EndPoints = dm.EndPoints[:len(dm.EndPoints)-1]
					shrink := rand.Intn(len(dm.EndPoints))
					dm.EndPoints = dm.EndPoints[:len(dm.EndPoints)-shrink]
				}
				// Add a new endpoint
				newEndpoint := tp.EndPoint{
					NamespaceName:    "test-namespace",
					EndPointName:     fmt.Sprintf("dynamic-endpoint-%d", counter),
					ContainerName:    fmt.Sprintf("dynamic-container-%d", counter),
					Identities:       []string{fmt.Sprintf("label=value-%d", counter)},
					SecurityPolicies: []tp.SecurityPolicy{},
				}
				dm.EndPoints = append(dm.EndPoints, newEndpoint)
				counter++
				dm.EndPointsLock.Unlock()
			}
		}
	}()

	// Let the race condition test run for a short time
	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	t.Log("UpdateSecurityPolicy race condition test completed without panics")
}

// TestUpdateHostSecurityPoliciesRaceCondition tests race conditions in UpdateHostSecurityPolicies
func TestUpdateHostSecurityPoliciesRaceCondition(t *testing.T) {
	dm := &KubeArmorDaemon{
		HostSecurityPolicies:     []tp.HostSecurityPolicy{},
		HostSecurityPoliciesLock: &sync.RWMutex{},
		Node: tp.Node{
			Identities: []string{"hostname=test-node"},
		},
	}

	// Initialize with test host policies
	for i := 0; i < 20; i++ {
		policy := tp.HostSecurityPolicy{
			Metadata: map[string]string{
				"policyName": fmt.Sprintf("host-policy-%d", i),
			},
			Spec: tp.HostSecuritySpec{
				NodeSelector: tp.NodeSelectorType{
					Identities: []string{"hostname=test-node"},
				},
			},
		}
		dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, policy)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: Update host security policies
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				dm.UpdateHostSecurityPolicies()
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Goroutine 2: Modify host policies
	wg.Add(1)
	go func() {
		defer wg.Done()
		counter := 100
		for {
			select {
			case <-stopCh:
				return
			default:
				dm.HostSecurityPoliciesLock.Lock()
				if len(dm.HostSecurityPolicies) > 0 {
					// Remove a policy
					dm.HostSecurityPolicies = dm.HostSecurityPolicies[:len(dm.HostSecurityPolicies)-1]
				}
				// Add a new policy
				newPolicy := tp.HostSecurityPolicy{
					Metadata: map[string]string{
						"policyName": fmt.Sprintf("dynamic-host-policy-%d", counter),
					},
					Spec: tp.HostSecuritySpec{
						NodeSelector: tp.NodeSelectorType{
							Identities: []string{"hostname=test-node"},
						},
					},
				}
				dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, newPolicy)
				counter++
				dm.HostSecurityPoliciesLock.Unlock()
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Run test
	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	t.Log("UpdateHostSecurityPolicies race condition test completed without panics")
}

// TestUpdateDefaultPostureRaceCondition tests race conditions in UpdateDefaultPosture
func TestUpdateDefaultPostureRaceCondition(t *testing.T) {
	// Skip this test for now due to external dependencies (Logger)
	t.Skip("Skipping UpdateDefaultPosture test due to external dependencies")

	dm := &KubeArmorDaemon{
		EndPoints:           []tp.EndPoint{},
		EndPointsLock:       &sync.RWMutex{},
		DefaultPostures:     map[string]tp.DefaultPosture{},
		DefaultPosturesLock: &sync.Mutex{},
	}

	// Initialize with test endpoints
	for i := 0; i < 30; i++ {
		endpoint := tp.EndPoint{
			NamespaceName:  "test-namespace",
			EndPointName:   fmt.Sprintf("test-endpoint-%d", i),
			ContainerName:  fmt.Sprintf("test-container-%d", i),
			DefaultPosture: tp.DefaultPosture{FileAction: "allow"},
		}
		dm.EndPoints = append(dm.EndPoints, endpoint)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Goroutine 1: Update default postures
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
				newPosture := tp.DefaultPosture{FileAction: "block"}
				dm.UpdateDefaultPosture("add", "test-namespace", newPosture, true)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Goroutine 2: Modify endpoints
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
					// Remove an endpoint
					dm.EndPoints = dm.EndPoints[:len(dm.EndPoints)-1]
				}
				// Add a new endpoint
				newEndpoint := tp.EndPoint{
					NamespaceName:  "test-namespace",
					EndPointName:   fmt.Sprintf("dynamic-endpoint-%d", counter),
					ContainerName:  fmt.Sprintf("dynamic-container-%d", counter),
					DefaultPosture: tp.DefaultPosture{FileAction: "allow"},
				}
				dm.EndPoints = append(dm.EndPoints, newEndpoint)
				counter++
				dm.EndPointsLock.Unlock()
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Run test
	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	t.Log("UpdateDefaultPosture race condition test completed without panics")
}

// TestConcurrentEndpointAccess tests general concurrent access patterns
func TestConcurrentEndpointAccess(t *testing.T) {
	dm := &KubeArmorDaemon{
		EndPoints:     []tp.EndPoint{},
		EndPointsLock: &sync.RWMutex{},
	}

	var wg sync.WaitGroup
	numGoroutines := 10
	operations := 1000

	// Create multiple goroutines that concurrently access endpoints
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				// Read operation - copy endpoints safely
				dm.EndPointsLock.RLock()
				endPointsCopy := make([]tp.EndPoint, len(dm.EndPoints))
				copy(endPointsCopy, dm.EndPoints)
				dm.EndPointsLock.RUnlock()

				// Process the copy (simulate work)
				for _, ep := range endPointsCopy {
					_ = ep.NamespaceName // Do something with the endpoint
				}

				// Write operation - modify endpoints
				if j%10 == 0 { // Every 10th operation is a write
					dm.EndPointsLock.Lock()
					newEndpoint := tp.EndPoint{
						NamespaceName: fmt.Sprintf("ns-%d", id),
						EndPointName:  fmt.Sprintf("ep-%d-%d", id, j),
						ContainerName: fmt.Sprintf("container-%d-%d", id, j),
					}
					dm.EndPoints = append(dm.EndPoints, newEndpoint)
					dm.EndPointsLock.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()
	t.Logf("Concurrent access test completed. Final endpoint count: %d", len(dm.EndPoints))
}
