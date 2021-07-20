module github.com/kubearmor/KubeArmor/KubeArmor

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/audit => ./audit
	github.com/kubearmor/KubeArmor/KubeArmor/common => ./common
	github.com/kubearmor/KubeArmor/KubeArmor/core => ./core
	github.com/kubearmor/KubeArmor/KubeArmor/discover => ./discovery
	github.com/kubearmor/KubeArmor/KubeArmor/enforcer => ./enforcer
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ./feeder
	github.com/kubearmor/KubeArmor/KubeArmor/log => ./log
	github.com/kubearmor/KubeArmor/KubeArmor/monitor => ./monitor
	github.com/kubearmor/KubeArmor/KubeArmor/types => ./types
	github.com/kubearmor/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/containerd/containerd v1.5.2
	github.com/containerd/typeurl v1.0.2
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hpcloud/tail v1.0.0
	github.com/iovisor/gobpf v0.2.0
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-00010101000000-000000000000
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20200929063507-e6143ca7d51d
	go.uber.org/zap v1.18.1
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	golang.org/x/sys v0.0.0-20210426230700-d19ff857e887
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210108203827-ffc7fda8c3d7 // indirect
	google.golang.org/grpc v1.34.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
)
