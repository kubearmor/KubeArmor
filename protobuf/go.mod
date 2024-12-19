module github.com/kubearmor/KubeArmor/protobuf

go 1.21.0

toolchain go1.21.12

replace (
	github.com/kubearmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/protobuf => ./
	github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.14.24
	github.com/pkg/sftp => github.com/pkg/sftp v1.11.0
	golang.org/x/image => golang.org/x/image v0.7.0
)

require (
	github.com/golang/protobuf v1.5.4
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.34.2
)

require (
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240725223205-93522f1f2a9f // indirect
)
