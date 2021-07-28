module github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor

go 1.16

require (
	github.com/aquasecurity/libbpfgo v0.1.2-0.20210728125149-cd17c665a141 // indirect
	github.com/kubearmor/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
)

replace (
	github.com/kubearmor/KubeArmor/KubeArmor/common => ../common
	github.com/kubearmor/KubeArmor/KubeArmor/eventAuditor => ./
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
	github.com/kubearmor/KubeArmor/KubeArmor/types => ../types
	github.com/kubearmor/KubeArmor/protobuf => ../../protobuf
)
