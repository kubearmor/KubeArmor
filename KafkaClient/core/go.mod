module github.com/accuknox/KubeArmor/KafkaClient/core

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KafkaClient => ../
	github.com/accuknox/KubeArmor/KafkaClient/core => ./
	github.com/accuknox/KubeArmor/KafkaClient/common => ../common
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)
