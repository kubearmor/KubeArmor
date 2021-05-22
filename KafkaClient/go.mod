module github.com/accuknox/KubeArmor/KafkaClient

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../
	github.com/accuknox/KubeArmor/KafkaClient => ./
	github.com/accuknox/KubeArmor/KafkaClient/common => ./common
	github.com/accuknox/KubeArmor/KafkaClient/core => ./core
	github.com/accuknox/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/accuknox/KubeArmor/KafkaClient/common v0.0.0-00010101000000-000000000000 // indirect
	github.com/accuknox/KubeArmor/KafkaClient/core v0.0.0-00010101000000-000000000000 // indirect
	github.com/accuknox/KubeArmor/protobuf v0.0.0-00010101000000-000000000000 // indirect
	github.com/confluentinc/confluent-kafka-go v1.7.0 // indirect
	google.golang.org/grpc v1.35.0 // indirect
	gopkg.in/confluentinc/confluent-kafka-go.v1 v1.7.0 // indirect
)
