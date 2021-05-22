module github.com/accuknox/KubeArmor/KafkaClient/common

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KafkaClient => ../
	github.com/accuknox/KubeArmor/KafkaClient/common => ./
)
