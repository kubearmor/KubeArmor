module github.com/kubearmor/KubeArmor/protobuf

go 1.20

replace (
	github.com/kubearmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/protobuf => ./
	github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.14.15
	github.com/pkg/sftp => github.com/pkg/sftp v1.11.0
	golang.org/x/image => golang.org/x/image v0.7.0
)

require (
	google.golang.org/grpc v1.55.0
	google.golang.org/protobuf v1.30.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
)
