module github.com/accuknox/KubeArmor/KubeArmor/monitor

go 1.15

replace (
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/common => ../common
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/accuknox/KubeArmor/KubeArmor/log => ../log
	github.com/accuknox/KubeArmor/KubeArmor/types => ../types
	github.com/accuknox/KubeArmor/LogServer/server => ../../LogServer/server
	github.com/accuknox/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/accuknox/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/accuknox/gobpf v0.0.0-20210111140304-a96e23829290
)
