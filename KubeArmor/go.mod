module github.com/kubearmor/KubeArmor/KubeArmor

go 1.16

replace (
	github.com/kubearmor/KubeArmor => ../../
	github.com/kubearmor/KubeArmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/KubeArmor/common => ./common
	github.com/kubearmor/KubeArmor/KubeArmor/core => ./core
	github.com/kubearmor/KubeArmor/KubeArmor/discover => ./discovery
	github.com/kubearmor/KubeArmor/KubeArmor/enforcer => ./enforcer
	github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm => ./enforcer/bpflsm
	github.com/kubearmor/KubeArmor/KubeArmor/feeder => ./feeder
	github.com/kubearmor/KubeArmor/KubeArmor/kvmAgent => ./kvmAgent
	github.com/kubearmor/KubeArmor/KubeArmor/log => ./log
	github.com/kubearmor/KubeArmor/KubeArmor/monitor => ./monitor
	github.com/kubearmor/KubeArmor/KubeArmor/policy => ./policy
	github.com/kubearmor/KubeArmor/KubeArmor/types => ./types
	github.com/kubearmor/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/cilium/ebpf v0.9.0
	github.com/containerd/containerd v1.5.13
	github.com/containerd/typeurl v1.0.2
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/iovisor/gobpf v0.2.0
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20211217093440-d99a1cb5f908
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/spf13/viper v1.4.0
	go.uber.org/zap v1.18.1
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/grpc v1.47.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
	k8s.io/cri-api v0.24.0
)
