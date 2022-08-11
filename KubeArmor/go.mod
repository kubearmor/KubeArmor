module github.com/kubearmor/KubeArmor/KubeArmor

go 1.18

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
	github.com/google/uuid v1.3.0
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20211217093440-d99a1cb5f908
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/spf13/viper v1.4.0
	go.uber.org/zap v1.18.1
	google.golang.org/grpc v1.48.0
	k8s.io/api v0.21.2
	k8s.io/apimachinery v0.21.2
	k8s.io/client-go v0.21.2
	k8s.io/cri-api v0.24.0
)

require (
	github.com/Microsoft/go-winio v0.4.17 // indirect
	github.com/containerd/ttrpc v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/magiconair/properties v1.8.0 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/sys v0.0.0-20220412211240-33da011f77ad // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/appengine v1.6.6 // indirect
	google.golang.org/genproto v0.0.0-20220107163113-42d7afdf6368 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.8.0 // indirect
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.0 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)
