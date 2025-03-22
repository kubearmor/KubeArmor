// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package metrics

import (
	"context"
	"log"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sync"
	"time"
)

// Import KubeArmor policy types
import (
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
)

// Use the existing KubeArmor policy types
type Policy = securityv1.KubeArmorPolicy
type HostPolicy = securityv1.KubeArmorHostPolicy

// PolicyCollector collects and updates KubeArmor policy metrics
type PolicyCollector struct {
	client   client.Client // K8s client, used to query resources
	interval time.Duration // Update metrics interval
	stopCh   chan struct{} // Channel for stopping the collector
	stopOnce sync.Once     // Ensure only one stop
}

// NewPolicyCollector creates a new policy collector
func NewPolicyCollector(client client.Client, interval time.Duration) *PolicyCollector {
	return &PolicyCollector{
		client:   client,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start starts the policy collector
func (pc *PolicyCollector) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(pc.interval)
		defer ticker.Stop()

		// Update once immediately on start
		pc.UpdateMetrics(ctx)

		for {
			select {
			case <-ticker.C:
				pc.UpdateMetrics(ctx)
			case <-pc.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Println("PolicyCollector started, updating metrics every", pc.interval)
}

// Stop stops the collector
func (pc *PolicyCollector) Stop() {
	pc.stopOnce.Do(func() {
		close(pc.stopCh)
		log.Println("PolicyCollector stopped")
	})
}

// Update policy metrics
func (pc *PolicyCollector) UpdateMetrics(ctx context.Context) {
	// Add retry logic
	var err error
	retries := 3

	// Container policies
	containerPolicies := &securityv1.KubeArmorPolicyList{}
	for i := 0; i < retries; i++ {
		err = pc.client.List(ctx, containerPolicies)
		if err == nil {
			break
		}
		log.Printf("Error getting container policies (attempt %d/%d): %v", i+1, retries, err)
		time.Sleep(500 * time.Millisecond)
	}

	// Get host policies (KubeArmorHostPolicy)
	hostPolicies := &securityv1.KubeArmorHostPolicyList{}
	if err := pc.client.List(ctx, hostPolicies); err != nil {
		log.Printf("Error getting host policies: %v", err)
	}

	// Get cluster policies (KubeArmorClusterPolicy)
	clusterPolicies := &securityv1.KubeArmorClusterPolicyList{}
	if err := pc.client.List(ctx, clusterPolicies); err != nil {
		log.Printf("Error getting cluster policies: %v", err)
	}

	// Calculate total policy count
	totalPolicies := len(containerPolicies.Items) + len(hostPolicies.Items) + len(clusterPolicies.Items)
	TotalPoliciesApplied.Set(float64(totalPolicies))

	// Update policy type metrics
	PoliciesByType.Reset()
	PoliciesByType.WithLabelValues("container").Set(float64(len(containerPolicies.Items)))
	PoliciesByType.WithLabelValues("host").Set(float64(len(hostPolicies.Items)))
	PoliciesByType.WithLabelValues("cluster").Set(float64(len(clusterPolicies.Items)))

	// Count policies by namespace
	PoliciesByNamespace.Reset()
	namespaceMap := make(map[string]int)

	// Count container policies by namespace
	for _, policy := range containerPolicies.Items {
		namespace := policy.Namespace
		namespaceMap[namespace]++
	}

	// Count host policies by namespace
	for _, policy := range hostPolicies.Items {
		namespace := policy.Namespace
		namespaceMap[namespace]++
	}

	// Cluster policies have no namespace, use special category
	if len(clusterPolicies.Items) > 0 {
		namespaceMap["cluster-wide"] += len(clusterPolicies.Items)
	}

	// Update namespace metrics
	for namespace, count := range namespaceMap {
		PoliciesByNamespace.WithLabelValues(namespace).Set(float64(count))
	}

	// Count policies by action
	PoliciesByAction.Reset()
	actionMap := make(map[string]int)

	// Process container policies actions
	for _, policy := range containerPolicies.Items {
		action := string(policy.Spec.Action)
		if action == "" {
			action = "audit" // Default action
		}
		actionMap[action]++
	}

	// Process host policies actions
	for _, policy := range hostPolicies.Items {
		action := string(policy.Spec.Action)
		if action == "" {
			action = "audit"
		}
		actionMap[action]++
	}

	// Process cluster policies actions
	for _, policy := range clusterPolicies.Items {
		action := string(policy.Spec.Action)
		if action == "" {
			action = "audit"
		}
		actionMap[action]++
	}

	// Update action type metrics
	for action, count := range actionMap {
		PoliciesByAction.WithLabelValues(action).Set(float64(count))
	}

	log.Printf("Updated policy metrics: %d total policies (%d container, %d host, %d cluster)",
		totalPolicies, len(containerPolicies.Items), len(hostPolicies.Items), len(clusterPolicies.Items))
}
