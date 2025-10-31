module github.com/kubearmor/KubeArmor/protobuf

go 1.24.9

replace (
	github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.0.5
	github.com/kubearmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/protobuf => ./
	github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.14.32
	github.com/pkg/sftp => github.com/pkg/sftp v1.11.0
	golang.org/x/image => golang.org/x/image v0.7.0
)

require (
	github.com/golang/protobuf v1.5.4
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
)

require (
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250324211829-b45e905df463 // indirect
)
