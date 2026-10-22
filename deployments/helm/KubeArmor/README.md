## Install KubeArmor
Install KubeArmor using Helm chart repo. Also see [values](#Values) for your respective environment.
```
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor kubearmor/kubearmor -n kubearmor --create-namespace
```

Install KubeArmor using Helm charts locally (for testing)
```
cd deployments/helm/KubeArmor
helm upgrade --install kubearmor . -n kubearmor --create-namespace
```

## TLS and agent upgrades

The daemon defaults to mTLS, but this chart explicitly configures it through
`tls.enabled` (default `false`). With TLS enabled, the agent CA now mounts at
`/var/lib/kubearmor/tls/log`; relay certificates remain at `/var/lib/kubearmor/tls`.
Keep `kubearmor.tls.tlsCertPath` and the agent CA volume mount aligned when reusing
custom values. Kubernetes does not expose the standalone management endpoint and
does not need management certificates. Read the
[TLS migration guide](../../../getting-started/kubearmor-security-enhancements.md#kubernetes-configuration)
before upgrading the agent image or reusing values from an older chart.

## Values
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| tls.enabled | bool | false | Enable mTLS for the agent and relay |
| kubearmor.tls.tlsCertPath | string | /var/lib/kubearmor/tls/log | Agent log CA directory; must match the agent CA volume mount |
| kubearmor.tls.tlsCertProvider | string | self | Agent certificate provider |
| kubearmorRelay.tls.tlsCertPath | string | /var/lib/kubearmor/tls | Relay certificate directory |
| kubearmorRelay.tls.tlsCertProvider | string | external | Relay certificate provider |
| environment.name | string | generic | The target environment to install KubeArmor in. Possible values: generic, GKE, EKS, BottleRocket, k0s, k3s, minikube, microk8s |
| kubearmor.image.repository | string | kubearmor/kubearmor | kubearmor image repo |
| kubearmor.image.tag | string | stable | kubearmor image tag |
| kubearmor.imagePullPolicy | string | Always | kubearmor imagePullPolicy |
| kubearmor.args | list | [] | Specify additional args to the kubearmor daemon. See [kubearmor-args](#kubearmor-args) |
| kubearmor.configMap.defaultFilePosture | string | audit | Default file posture for KubeArmor |
| kubearmor.configMap.defaultNetworkPosture | string | audit | Default network posture for KubeArmor |
| kubearmor.configMap.defaultCapabilitiesPosture | string | audit | Default capabilities posture for KubeArmor |
| kubearmor.configMap.visibility | string | audit | Default visibility for KubeArmor |
| kubearmor.resources | object | { requests: { cpu: 10m, memory: 64Mi } } | kubearmor DaemonSet container resources requests/limits |
| kubearmorRelay.enable | bool | true | to enable/disable kubearmor-relay |
| kubearmorRelay.image.repository | string | kubearmor/kubearmor-relay | kubearmor-relay image repo |
| kubearmorRelay.image.tag | string | latest | kubearmor-relay image tag |
| kubearmorRelay.imagePullPolicy | string | Always | kubearmor-relay imagePullPolicy |
| kubearmorRelay.resources | object | { requests: { cpu: 10m, memory: 64Mi } } | kubearmor-relay container resources requests/limits |
| kubearmorInit.image.repository | string | kubearmor/kubearmor-init | kubearmor-init image repo |
| kubearmorInit.image.tag | string | stable | kubearmor-init image tag |
| kubearmorInit.imagePullPolicy | string | Always | kubearmor-init imagePullPolicy |
| kubeRbacProxy.image.repository | string | gcr.io/kubebuilder/kube-rbac-proxy | kube-rbac-proxy image repo |
| kubeRbacProxy.image.tag | string | v0.15.0 | kube-rbac-proxy image tag |
| kubeRbacProxy.imagePullPolicy | string | Always | kube-rbac-proxy imagePullPolicy |
| kubearmorController.replicas | int | 1 | kubearmor-controller replicas |
| kubearmorController.image.repository | string | kubearmor/kubearmor-controller | kubearmor-controller image repo |
| kubearmorController.image.tag | string | latest | kubearmor-controller image tag |
| kubearmorController.mutation.failurePolicy | string | Ignore | kubearmor-controller failure policy |
| kubearmorController.imagePullPolicy | string | Always | kubearmor-controller imagePullPolicy |
| kubearmorController.resources | object | { requests: { cpu: 10m, memory: 64Mi } } | kubearmor-controller container resources requests/limits |

## kubearmor-args

`-gRPC` selects the observability port. For the new management, TLS, and health
settings, see the [endpoint reference](../../../getting-started/kubearmor-security-enhancements.md#endpoints)
and use `kubearmor -h` from the agent version being deployed.

```
$ sudo ./kubearmor -h
Usage of ./kubearmor:
  -alertThrottling
        enabling Alert Throttling
  -bpfFsPath string
        Path to the BPF filesystem to use for storing maps (default "/sys/fs/bpf")
  -cluster string
        cluster name (default "default")
  -coverageTest
        enabling CoverageTest
  -criSocket string
        path to CRI socket (format: unix:///path/to/file.sock)
  -defaultCapabilitiesPosture string
        configuring default enforcement action in global capability context {allow|audit|block} (default "audit")
  -defaultFilePosture string
        configuring default enforcement action in global file context {allow|audit|block} (default "audit")
  -defaultNetworkPosture string
        configuring default enforcement action in global network context {allow|audit|block} (default "audit")
  -enableKubeArmorHostPolicy
        enabling KubeArmorHostPolicy
  -enableKubeArmorPolicy
        enabling KubeArmorPolicy (default true)
  -enableKubeArmorVm
        enabling KubeArmorVM
  -gRPC string
        gRPC port number (default "32767")
  -host string
        host name (default "kubearmor-dev-next")
  -hostDefaultCapabilitiesPosture string
        configuring default enforcement action in global capability context {allow|audit|block} (default "audit")
  -hostDefaultFilePosture string
        configuring default enforcement action in global file context {allow|audit|block} (default "audit")
  -hostDefaultNetworkPosture string
        configuring default enforcement action in global network context {allow|audit|block} (default "audit")
  -hostVisibility string
        Host Visibility to use [process,file,network,capabilities,none] (default "none" for k8s, "process,file,network,capabilities" for VM) (default "default")
  -k8s
        is k8s env? (default true)
  -kubeconfig string
        Paths to a kubeconfig. Only required if out-of-cluster.
  -logPath string
        log file path, {path|stdout|none} (default "none")
  -lsm string
        lsm preference order to use, available lsms [bpf, apparmor, selinux] (default "bpf,apparmor,selinux")
  -maxAlertPerSec int
        Maximum alerts allowed per second (default 10)
  -seLinuxProfileDir string
        SELinux profile directory (default "/tmp/kubearmor.selinux")
  -throttleSec int
        Time period for which subsequent alerts will be dropped (in sec) (default 30)
  -visibility string
        Container Visibility to use, available visibility [process,file,network,capabilities,none] (default "process,network")
```

## Verify if all the resources are up and running
```
kubectl get all -n kubearmor -l kubearmor-app
NAME                                        READY   STATUS    RESTARTS   AGE
pod/kubearmor-controller-7b48cf777f-bn7d8   2/2     Running   0          24s
pod/kubearmor-relay-5656cc5bf7-jl56q        1/1     Running   0          24s
pod/kubearmor-cnc7b                         1/1     Running   0          24s

NAME                                           TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
service/kubearmor-controller-metrics-service   ClusterIP   10.43.208.188   <none>        8443/TCP   24s

NAME                       DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR            AGE
daemonset.apps/kubearmor   1         1         1       1            1           kubernetes.io/os=linux   24s

NAME                                   READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/kubearmor-controller   1/1     1            1           24s
deployment.apps/kubearmor-relay        1/1     1            1           24s

NAME                                              DESIRED   CURRENT   READY   AGE
replicaset.apps/kubearmor-controller-7b48cf777f   1         1         1       24s
replicaset.apps/kubearmor-relay-5656cc5bf7        1         1         1       24s
```

## Remove KubeArmor
Uninstall KubeArmor using helm
```
helm uninstall kubearmor -n kubearmor
```
