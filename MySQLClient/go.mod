module github.com/accuknox/KubeArmor/MySQLClient

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../
	github.com/accuknox/KubeArmor/MySQLClient => ./
	github.com/accuknox/KubeArmor/MySQLClient/common => ./common
	github.com/accuknox/KubeArmor/MySQLClient/core => ./core
	github.com/accuknox/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/accuknox/KubeArmor/MySQLClient/common v0.0.0-00010101000000-000000000000 // indirect
	github.com/accuknox/KubeArmor/MySQLClient/core v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/protobuf v0.0.0-00010101000000-000000000000 // indirect
	github.com/go-sql-driver/mysql v1.6.0
	google.golang.org/grpc v1.35.0 // indirect
)
