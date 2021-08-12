module github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor

go 1.16

require (
	github.com/kubearmor/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/kubearmor/libbpf v0.0.0-20210812132630-835e5a3cb193
)

replace (
	github.com/kubearmor/KubeArmor/KubeArmor/common => ../common
	github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor => ./
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
	github.com/kubearmor/KubeArmor/KubeArmor/types => ../types
	github.com/kubearmor/KubeArmor/protobuf => ../../protobuf
)
