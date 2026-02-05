module github.com/kubearmor/KubeArmor/protobuf

go 1.24.12

replace (
	github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.0.5
	github.com/kubearmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/protobuf => ./
	github.com/mattn/go-sqlite3 => github.com/mattn/go-sqlite3 v1.14.18
	github.com/pkg/sftp => github.com/pkg/sftp v1.11.0
	golang.org/x/image => golang.org/x/image v0.7.0
)

require (
	github.com/golang/protobuf v1.5.4
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260203192932-546029d2fa20 // indirect
)
