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
)
