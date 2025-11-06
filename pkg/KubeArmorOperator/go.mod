module github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator

go 1.24.9

replace (
	github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.0.5
	github.com/kubearmor/KubeArmor/KubeArmor => ../../KubeArmor
	github.com/kubearmor/KubeArmor/deployments => ../../deployments
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController => ../KubeArmorController
)

require (
	github.com/kubearmor/KubeArmor/KubeArmor v0.0.0-20250701060635-600e11526ec1
	github.com/kubearmor/KubeArmor/deployments v0.0.0-20250701060635-600e11526ec1
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController v0.0.0-20250701060635-600e11526ec1
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.75.1
	k8s.io/api v0.34.1
	k8s.io/apiextensions-apiserver v0.34.1
	k8s.io/apimachinery v0.34.1
	k8s.io/client-go v0.34.1
	k8s.io/cri-api v0.34.1
	k8s.io/klog/v2 v2.130.1
	k8s.io/kubectl v0.34.1
	sigs.k8s.io/controller-runtime v0.22.1
)

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20250520111509-a70c2aa677fa // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.13.0 // indirect
	github.com/containerd/cgroups/v3 v3.0.5 // indirect
	github.com/containerd/containerd/api v1.9.0 // indirect
	github.com/containerd/continuity v0.4.5 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.1 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-events v0.0.0-20250808211157-605354379745 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/selinux v1.12.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.63.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	golang.org/x/net v0.46.0 // indirect
	golang.org/x/oauth2 v0.31.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.36.0 // indirect
	google.golang.org/genproto v0.0.0-20250908214217-97024824d090 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250908214217-97024824d090 // indirect
)

require (
	github.com/containers/storage v1.59.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.24.0 // indirect
	github.com/go-openapi/swag/conv v0.24.0 // indirect
	github.com/go-openapi/swag/fileutils v0.24.0 // indirect
	github.com/go-openapi/swag/jsonname v0.24.0 // indirect
	github.com/go-openapi/swag/jsonutils v0.24.0 // indirect
	github.com/go-openapi/swag/loading v0.24.0 // indirect
	github.com/go-openapi/swag/mangling v0.24.0 // indirect
	github.com/go-openapi/swag/netutils v0.24.0 // indirect
	github.com/go-openapi/swag/stringutils v0.24.0 // indirect
	github.com/go-openapi/swag/typeutils v0.24.0 // indirect
	github.com/go-openapi/swag/yamlutils v0.24.0 // indirect
	github.com/kubearmor/KubeArmor/protobuf v0.0.0-20250916032022-5864f940ceca // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
)

require (
	github.com/cilium/ebpf v0.19.1-0.20251013125301-c27ff922fc6a // indirect
	github.com/containerd/containerd v1.7.29
	github.com/containers/common v0.64.2
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.22.0 // indirect
	github.com/go-openapi/jsonreference v0.21.1 // indirect
	github.com/go-openapi/swag v0.24.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/time v0.13.0 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/kube-openapi v0.0.0-20250910181357-589584f1c912 // indirect
	k8s.io/utils v0.0.0-20250820121507-0af2bda4dd1d // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
