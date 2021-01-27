module github.com/accuknox/KubeArmor/KubeArmor/types

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/types => ./
)

require (
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
)
