module github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy

go 1.13

require (
	github.com/go-logr/logr v0.4.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.16.0
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
	k8s.io/klog/v2 v2.10.0 // indirect
	sigs.k8s.io/controller-runtime v0.10.0
)
