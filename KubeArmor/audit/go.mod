module github.com/kubearmor/KubeArmor/KubeArmor/monitor

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/common => ../common
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
	github.com/kubearmor/KubeArmor/KubeArmor/audit => ./
	github.com/kubearmor/KubeArmor/KubeArmor/types => ../types
	github.com/kubearmor/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/kubearmor/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/hpcloud/tail v1.0.0
)
