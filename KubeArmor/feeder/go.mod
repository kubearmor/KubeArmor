module github.com/accuknox/KubeArmor/KubeArmor/feeder

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ./
	github.com/accuknox/KubeArmor/KubeArmor/common => ../common
	github.com/accuknox/KubeArmor/KubeArmor/log => ../log
	github.com/accuknox/KubeArmor/KubeArmor/types => ../types
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/accuknox/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/protobuf v0.0.0-00010101000000-000000000000
	github.com/google/uuid v1.1.2
	google.golang.org/grpc v1.34.0
)
