module github.com/accuknox/KubeArmor/KubeArmor-relay-server

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor-relay-server => ./
	github.com/accuknox/KubeArmor/KubeArmor-relay-server/core => ./core
	github.com/accuknox/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/accuknox/KubeArmor/KubeArmor-relay-server/core v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/protobuf v0.0.0-00010101000000-000000000000 // indirect
	google.golang.org/grpc v1.35.0 // indirect
)
