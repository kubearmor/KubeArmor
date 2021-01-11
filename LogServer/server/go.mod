module github.com/accuknox/KubeArmor/LogServer/server

go 1.15

replace (
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ../../KubeArmor/feeder
	github.com/accuknox/KubeArmor/KubeArmor/log => ../../KubeArmor/log
	github.com/accuknox/KubeArmor/KubeArmor/types => ../../KubeArmor/types
	github.com/accuknox/KubeArmor/LogServer/server => ./
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/accuknox/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000 // indirect
	github.com/accuknox/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/protobuf v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.16.0 // indirect
	google.golang.org/grpc v1.34.0
	k8s.io/api v0.20.1 // indirect
)
