module github.com/accuknox/KubeArmor/KubeArmor

go 1.14

replace (
	github.com/accuknox/KubeArmor => ../../
	github.com/accuknox/KubeArmor/KubeArmor => ../
	github.com/accuknox/KubeArmor/KubeArmor/common => ./common
	github.com/accuknox/KubeArmor/KubeArmor/core => ./core
	github.com/accuknox/KubeArmor/KubeArmor/discover => ./discovery
	github.com/accuknox/KubeArmor/KubeArmor/enforcer => ./enforcer
	github.com/accuknox/KubeArmor/KubeArmor/feeder => ./feeder
	github.com/accuknox/KubeArmor/KubeArmor/log => ./log
	github.com/accuknox/KubeArmor/KubeArmor/monitor => ./monitor
	github.com/accuknox/KubeArmor/KubeArmor/types => ./types
	github.com/accuknox/KubeArmor/protobuf => ../protobuf
)

require (
	github.com/Microsoft/go-winio v0.4.16 // indirect
	github.com/accuknox/KubeArmor/KubeArmor/core v0.0.0-00010101000000-000000000000
	github.com/accuknox/KubeArmor/KubeArmor/log v0.0.0-00010101000000-000000000000
	github.com/containerd/containerd v1.4.3
	github.com/containerd/ttrpc v1.0.2 // indirect
	github.com/containerd/typeurl v1.0.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v20.10.2+incompatible
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/go-logr/logr v0.3.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/iovisor/gobpf v0.0.0-20210217075126-686d1e527d5f
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/sirupsen/logrus v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sys v0.0.0-20210110051926-789bb1bd4061 // indirect
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/genproto v0.0.0-20210108203827-ffc7fda8c3d7 // indirect
	google.golang.org/grpc v1.34.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gotest.tools/v3 v3.0.3 // indirect
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
)
