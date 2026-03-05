// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"fmt"
)

// ServiceInfo holds metadata for a Kubernetes Service resolved by IP.
type ServiceInfo struct {
	Name      string
	Namespace string
}

// Watcher monitors Kubernetes pod and service objects to provide
// IP-to-workload metadata resolution for the API Observer.
//
// TODO: implement full K8s informer-based watcher using client-go.
// Currently returns empty results (enrichment is non-fatal).
type Watcher struct {
	// TODO: pod and service informers.
}

// NewWatcher creates a new K8s Watcher.
// Returns an error if the Kubernetes client cannot be initialised.
//
// This is a stub implementation — always succeeds.
func NewWatcher() (*Watcher, error) {
	// TODO: initialise k8s client and informers.
	return nil, fmt.Errorf("K8s watcher not yet implemented")
}

// Start begins the informer goroutines.  Blocks until ctx is cancelled
// or the initial cache sync completes.
func (w *Watcher) Start(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("watcher is nil")
	}
	_ = ctx
	return nil
}

// GetPodURI returns "namespace/pod-name" for the given IP, or "" if unknown.
func (w *Watcher) GetPodURI(ip string) string {
	if w == nil {
		return ""
	}
	_ = ip
	return ""
}

// GetServicesByIP returns all services whose ClusterIP matches the given IP.
func (w *Watcher) GetServicesByIP(ip string) []ServiceInfo {
	if w == nil {
		return nil
	}
	_ = ip
	return nil
}
