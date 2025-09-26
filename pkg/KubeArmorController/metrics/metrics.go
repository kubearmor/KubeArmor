package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	PolicyCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policies_total",
			Help: "Total number of KubeArmor policies by type",
		},
		[]string{"type"},
	)

	PolicyInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubearmor_policy_info",
			Help: "Information about KubeArmor policies",
		},
		[]string{"name", "namespace", "type", "status"},
	)
)

func init() {
	metrics.Registry.MustRegister(PolicyCount, PolicyInfo)
}