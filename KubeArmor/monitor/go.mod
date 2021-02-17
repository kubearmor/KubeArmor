module github.com/accuknox/KubeArmor/KubeArmor/monitor

go 1.15

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/common => ../common
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/accuknox/KubeArmor/KubeArmor/log => ../log
	github.com/accuknox/KubeArmor/KubeArmor/monitor => ./
	github.com/accuknox/KubeArmor/KubeArmor/types => ../types
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/accuknox/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/hpcloud/tail v1.0.0
	github.com/iovisor/gobpf v0.0.0-20210109143822-fb892541d416
)
