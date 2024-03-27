module github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator

go 1.21

toolchain go1.21.8

replace (
	github.com/kubearmor/KubeArmor/KubeArmor => ../../KubeArmor
	github.com/kubearmor/KubeArmor/deployments => ../../deployments
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController => ../KubeArmorController
)

require (
	github.com/kubearmor/KubeArmor/KubeArmor v0.0.0-20240110164432-c2c1b121cd94
	github.com/kubearmor/KubeArmor/deployments v0.0.0-20230809083125-e2d5d5709d2c
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController v0.0.0-20240110164432-c2c1b121cd94
	github.com/spf13/cobra v1.8.0
	go.uber.org/zap v1.26.0
	k8s.io/api v0.29.3
	k8s.io/apiextensions-apiserver v0.29.3
	k8s.io/apimachinery v0.29.3
	k8s.io/client-go v0.29.3
	k8s.io/kubectl v0.29.3
	sigs.k8s.io/controller-runtime v0.15.3
)

require (
	github.com/cilium/ebpf v0.12.3 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/emicklei/go-restful/v3 v3.11.2 // indirect
	github.com/evanphx/json-patch v5.7.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-openapi/jsonpointer v0.20.2 // indirect
	github.com/go-openapi/jsonreference v0.20.4 // indirect
	github.com/go-openapi/swag v0.22.9 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/pprof v0.0.0-20230323073829-e72429f035bd // indirect
	github.com/google/uuid v1.5.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/ginkgo/v2 v2.14.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.11.0 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.18.2 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240119083558-1b970713d09a // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/oauth2 v0.16.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/term v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.120.0 // indirect
	k8s.io/kube-openapi v0.0.0-20240105020646-a37d4de58910 // indirect
	k8s.io/utils v0.0.0-20240102154912-e7106e64919e // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)
