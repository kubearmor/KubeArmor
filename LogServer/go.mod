module github.com/accuknox/KubeArmor/LogServer

go 1.15

replace (
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/LogServer/server => ./server
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ../KubeArmor/feeder
	github.com/accuknox/KubeArmor/KubeArmor/log => ../KubeArmor/log
	github.com/accuknox/KubeArmor/KubeArmor/types => ../KubeArmor/types
	github.com/accuknox/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/accuknox/KubeArmor/LogServer/server v0.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.4.3 // indirect
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/sys v0.0.0-20210108172913-0df2131ae363 // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210108203827-ffc7fda8c3d7 // indirect
	google.golang.org/grpc v1.34.0
	google.golang.org/protobuf v1.25.0
)
