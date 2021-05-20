module github.com/accuknox/KubeArmor/MySQLClient/common

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/MySQLClient => ../
	github.com/accuknox/KubeArmor/MySQLClient/common => ./
)
