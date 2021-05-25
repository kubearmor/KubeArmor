module github.com/accuknox/KubeArmor/KubeArmor-relay-server/core

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor-relay-server => ../
	github.com/accuknox/KubeArmor/KubeArmor-relay-server/core => ./
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)

require (
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
)
