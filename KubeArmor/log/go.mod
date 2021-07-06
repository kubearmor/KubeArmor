module github.com/kubearmor/KubeArmor/KubeArmor/log

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/log => ./
)

require go.uber.org/zap v1.16.0
