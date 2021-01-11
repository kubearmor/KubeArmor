module github.com/accuknox/KubeArmor/KubeArmor/log

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
)

require go.uber.org/zap v1.16.0
