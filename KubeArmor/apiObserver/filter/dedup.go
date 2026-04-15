// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package filter

import (
	"sync"
	"time"
)

// DedupCache is a lightweight time-based deduplication cache. It holds
// fingerprints of recently seen events and drops duplicates within the
// TTL window.
//
// KubeArmor captures both sides of a TCP connection (client & server
// sockets), producing two identical events per request. This cache
// eliminates the second observation.
type DedupCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
	done    chan struct{}
}

// NewDedupCache creates a dedup cache with the given TTL.
func NewDedupCache(ttl time.Duration) *DedupCache {
	d := &DedupCache{
		entries: make(map[string]time.Time, 256),
		ttl:     ttl,
		done:    make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// IsDuplicate returns true if the key was seen within the TTL window.
// If not seen, it records the key and returns false.
func (d *DedupCache) IsDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if t, seen := d.entries[key]; seen && now.Sub(t) < d.ttl {
		return true
	}
	d.entries[key] = now
	return false
}

// Stop terminates the cleanup goroutine.
func (d *DedupCache) Stop() {
	close(d.done)
}

// cleanupLoop periodically evicts expired entries to prevent memory leak.
func (d *DedupCache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.mu.Lock()
			now := time.Now()
			for k, t := range d.entries {
				if now.Sub(t) > d.ttl {
					delete(d.entries, k)
				}
			}
			d.mu.Unlock()
		case <-d.done:
			return
		}
	}
}
