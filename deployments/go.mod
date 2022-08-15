module github.com/kubearmor/KubeArmor/deployments

go 1.18

replace (
	github.com/kubearmor/KubeArmor => ../
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController => ../pkg/KubeArmorController
	github.com/kubearmor/KubeArmor/pkg/KubeArmorHostPolicy => ../pkg/KubeArmorHostPolicy
	github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy => ../pkg/KubeArmorPolicy
)

require (
	github.com/clarketm/json v1.17.1
	github.com/kubearmor/KubeArmor/KubeArmor v0.0.0-20221130063629-a2dd0301b858
	github.com/kubearmor/KubeArmor/pkg/KubeArmorController v0.0.0-20220908103453-7b92e248beb9
	k8s.io/api v0.25.0
	k8s.io/apimachinery v0.25.0
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.0.5 // indirect
	github.com/spf13/afero v1.9.2 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.13.0 // indirect
	github.com/subosito/gotenv v1.4.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.23.0 // indirect
	golang.org/x/net v0.0.0-20220907135653-1e95f45603a7 // indirect
	golang.org/x/sys v0.0.0-20220907062415-87db552b00fd // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.25.0 // indirect
	k8s.io/klog/v2 v2.80.0 // indirect
	k8s.io/utils v0.0.0-20220823124924-e9cbc92d1a73 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)
