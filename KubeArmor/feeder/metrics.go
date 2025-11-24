// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AlertsTotal tracks total number of KubeArmor alerts generated per node
	AlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubearmor_alerts_total",
			Help: "Total number of KubeArmor alerts generated per node",
		},
		[]string{"node"},
	)

	// PoliciesTotal tracks total number of active KubeArmor policies by type
	PoliciesTotal = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_total",
			Help: "Total number of active KubeArmor policies by type",
		},
		[]string{"type"},
	)

	// PolicyInfo tracks detailed information about KubeArmor policies
	PolicyInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policy_info",
			Help: "Information about KubeArmor policies",
		},
		[]string{"name", "namespace", "type", "status"},
	)

	// RuleViolations tracks total number of policy rule violations by policy, type, and action
	RuleViolations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubearmor_rule_violations_total",
			Help: "Total number of policy rule violations by policy, type, and action",
		},
		[]string{"policy_name", "rule_type", "action"},
	)
)

// InitializeMetrics sets initial zero values for all metrics to ensure they appear in /metrics endpoint
// This must be called after metrics are defined but before the server starts serving requests
func InitializeMetrics() {
	// Initialize policy count metrics with zero for all policy types
	PoliciesTotal.WithLabelValues("KubeArmorPolicy").Set(0)
	PoliciesTotal.WithLabelValues("KubeArmorHostPolicy").Set(0)
	PoliciesTotal.WithLabelValues("KubeArmorClusterPolicy").Set(0)

	// Note: PolicyInfo is a gauge with 4 labels that populates dynamically
	// Note: AlertsTotal and RuleViolations are counters that appear on first use
}
