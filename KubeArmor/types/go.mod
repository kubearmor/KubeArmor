module github.com/kubearmor/KubeArmor/KubeArmor/types

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/types => ./
)

require (
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
)
