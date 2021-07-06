module github.com/kubearmor/KubeArmor/KubeArmor/core

go 1.15

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/audit => ../audit
	github.com/kubearmor/KubeArmor/KubeArmor/common => ../common
	github.com/kubearmor/KubeArmor/KubeArmor/core => ./
	github.com/kubearmor/KubeArmor/KubeArmor/discover => ../discovery
	github.com/kubearmor/KubeArmor/KubeArmor/enforcer => ../enforcer
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ../feeder
	github.com/kubearmor/KubeArmor/KubeArmor/log => ../log
	github.com/kubearmor/KubeArmor/KubeArmor/monitor => ../monitor
	github.com/kubearmor/KubeArmor/KubeArmor/types => ../types
	github.com/kubearmor/KubeArmor/protobuf => ../../protobuf
)

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/kubearmor/KubeArmor/KubeArmor/audit v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/common v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/enforcer v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/feeder v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/monitor v0.0.0-00010101000000-000000000000
	github.com/kubearmor/KubeArmor/KubeArmor/types v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.4.3
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.2+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	google.golang.org/grpc v1.34.0
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
)
