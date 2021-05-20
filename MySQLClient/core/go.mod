module github.com/accuknox/KubeArmor/MySQLClient/core

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/MySQLClient => ../
	github.com/accuknox/KubeArmor/MySQLClient/core => ./
	github.com/accuknox/KubeArmor/MySQLClient/common => ../common
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)
