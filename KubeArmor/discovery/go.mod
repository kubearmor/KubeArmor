module github.com/kubearmor/KubeArmor/KubeArmor/discovery

go 1.15

replace (
    github.com/kubearmor/KubeArmor => ../../
    github.com/kubearmor/KubeArmor/KubeArmor => ../
    github.com/kubearmor/KubeArmor/KubeArmor/discovery => ./
)
