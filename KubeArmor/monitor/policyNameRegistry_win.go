//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"strings"
	"sync"
)

// PolicyNameRegistry maps NT device paths (and pattern/directory prefixes)
// to the KubeArmor policy name that caused the rule. The enforcer populates
// this when sending rules to the driver, and the monitor queries it when
// processing blocked-file or blocked-process events to resolve the correct
// policy name.
//
// Supported match types:
//   - "path"      — exact NT path (file rules)
//   - "directory" — NT path prefix (directory rules)
//   - "pattern"   — glob pattern prefix (matchPatterns rules)
//   - "suffix"    — filename suffix (process rules; driver uses suffix matching)
//
// This lives in the monitor package because the enforcer already imports
// monitor (no circular dependency).
type PolicyNameRegistry struct {
	mu      sync.RWMutex
	entries []policyNameEntry
}

type policyNameEntry struct {
	// path is the NT path, directory prefix, pattern, or filename suffix sent to the driver.
	path string
	// matchType: "path", "directory", "pattern", or "suffix".
	matchType string
	// policyName is the KubeArmor policy metadata name.
	policyName string
}

var globalPolicyNameRegistry = &PolicyNameRegistry{}

// GetPolicyNameRegistry returns the singleton registry.
func GetPolicyNameRegistry() *PolicyNameRegistry {
	return globalPolicyNameRegistry
}

// Clear removes all entries (called before policy reload).
func (r *PolicyNameRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = r.entries[:0]
}

// Register adds a path → policyName mapping.
// matchType should be "path", "directory", "pattern", or "suffix".
func (r *PolicyNameRegistry) Register(ntPath, matchType, policyName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, policyNameEntry{
		path:       strings.ToLower(ntPath),
		matchType:  matchType,
		policyName: policyName,
	})
}

// Lookup finds the best-matching policy name for a given NT resource path.
// Returns the policy name, or "" if no match is found.
func (r *PolicyNameRegistry) Lookup(resourcePath string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lowerResource := strings.ToLower(resourcePath)
	bestMatch := ""
	bestLen := 0

	for _, e := range r.entries {
		switch e.matchType {
		case "path":
			if lowerResource == e.path {
				return e.policyName // exact match wins immediately
			}
		case "directory":
			if strings.HasPrefix(lowerResource, e.path) && len(e.path) > bestLen {
				bestMatch = e.policyName
				bestLen = len(e.path)
			}
		case "pattern":
			// Pattern matching is complex (glob); use simple prefix of
			// the non-wildcard portion for a best-effort match.
			prefix := e.path
			if idx := strings.IndexAny(prefix, "*?"); idx >= 0 {
				prefix = prefix[:idx]
			}
			if prefix != "" && strings.HasPrefix(lowerResource, prefix) && len(prefix) > bestLen {
				bestMatch = e.policyName
				bestLen = len(prefix)
			}
		case "suffix":
			// The driver matches process rules by filename suffix (e.g. "notepad.exe").
			// We do the same: check if the resource path ends with the registered suffix.
			if strings.HasSuffix(lowerResource, "\\"+e.path) || lowerResource == e.path {
				if len(e.path) > bestLen {
					bestMatch = e.policyName
					bestLen = len(e.path)
				}
			}
		}
	}
	return bestMatch
}
