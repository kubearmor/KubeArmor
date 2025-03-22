package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// Total number of applied policies
	TotalPoliciesApplied = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_applied_total",
			Help: "Total number of KubeArmor security policies currently applied",
		},
	)

	// Number of policies categorized by type (container/host)
	PoliciesByType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_by_type",
			Help: "Number of KubeArmor security policies by type",
		},
		[]string{"type"}, // type: container/host
	)

	// Number of policies categorized by namespace
	PoliciesByNamespace = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_by_namespace",
			Help: "Number of KubeArmor security policies by namespace",
		},
		[]string{"namespace"}, // namespace name
	)

	// Number of policies categorized by action
	PoliciesByAction = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_by_action",
			Help: "Number of KubeArmor security policies by action",
		},
		[]string{"action"}, // action: allow/block/audit
	)
)

func init() {
	// Register custom metrics with the controller-runtime metrics registry
	metrics.Registry.MustRegister(TotalPoliciesApplied)
	metrics.Registry.MustRegister(PoliciesByType)
	metrics.Registry.MustRegister(PoliciesByNamespace)
	metrics.Registry.MustRegister(PoliciesByAction)
}
