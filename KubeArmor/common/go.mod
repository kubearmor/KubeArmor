module github.com/accuknox/KubeArmor/KubeArmor/common

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/common => ./
	github.com/accuknox/KubeArmor/KubeArmor/log => ../log
)

require (
	github.com/accuknox/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	go.uber.org/zap v1.16.0 // indirect
)
