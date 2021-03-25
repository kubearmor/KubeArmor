module github.com/accuknox/KubeArmor/LogClient/core

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/LogClient => ../
	github.com/accuknox/KubeArmor/LogClient/core => ./
	github.com/accuknox/KubeArmor/LogClient/common => ../common
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)
