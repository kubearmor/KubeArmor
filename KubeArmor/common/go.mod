module github.com/kubearmor/KubeArmor/KubeArmor/common

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/common => ./
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
)

require (
	github.com/kubearmor/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/sys v0.0.0-20190412213103-97732733099d
)
