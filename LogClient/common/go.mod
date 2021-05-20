module github.com/accuknox/KubeArmor/LogClient/common

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/LogClient => ../
	github.com/accuknox/KubeArmor/LogClient/common => ./
)
