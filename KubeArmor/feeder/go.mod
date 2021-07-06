module github.com/kubearmor/KubeArmor/KubeArmor/feeder

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ./
	github.com/kubearmor/KubeArmor/KubeArmor/common => ../common
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
	github.com/kubearmor/KubeArmor/KubeArmor/types => ../types
	github.com/kubearmor/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/kubearmor/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.1.2
	google.golang.org/grpc v1.34.0
)
