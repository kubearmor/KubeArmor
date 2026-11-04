# Install KubeArmorOperator

Install KubeArmorOperator using the official `kubearmor` Helm chart repo. Also see [values](#values) for your respective environment.

```bash
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace
```

Install KubeArmorOperator using Helm charts locally (for testing)

```bash
cd deployments/helm/KubeArmorOperator
helm upgrade --install kubearmor-operator . -n kubearmor --create-namespace
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| kubearmorOperator.name | string | kubearmor-operator | name of the operator's deployment |
| kubearmorOperator.image.repository | string | kubearmor/kubearmor-operator | image repository to pull KubeArmorOperator from |
| kubearmorOperator.image.tag | string | latest | KubeArmorOperator image tag |
| kubearmorOperator.imagePullPolicy | string | IfNotPresent | pull policy for operator image |
| kubearmorOperator.socketFile | string | "" | absolute path to the CRI socket file (e.g., /var/run/containerd/containerd.sock). If not set, the operator will auto-detect the CRI socket |
| kubearmorOperator.podLabels | object | {} | additional pod labels |
| kubearmorOperator.podAnnotations | object | {} | additional pod annotations |
| kubearmorOperator.resources | object | {} | operator container resources |
| kubearmorOperator.podSecurityContext | object | {} | pod security context |
| kubearmorOperator.securityContext | object | {} | operator container security context |
| kubearmorConfig | object | [values.yaml](values.yaml) | KubeArmor default configurations |
| kubearmorOperator.annotateResource | bool | false | flag to control RBAC permissions conditionally, use `--annotateResource=<value>` arg as well to pass the same value to operator configuration |
| autoDeploy | bool | false | Auto deploy KubeArmor with default configurations |

The operator needs a `KubeArmorConfig` object in order to create resources related to KubeArmor. A default config is present in Helm `values.yaml` which can be overridden during Helm install. To install KubeArmor with default configuration use `--set autoDeploy=true` flag with helm install/upgrade command. It is possible to specify configuration even after KubeArmor resources have been installed by directly editing the created `KubeArmorConfig` CR.

By Default the helm does not deploys the default KubeArmor Configurations (KubeArmorConfig CR) and once installed, the operator waits for the user to create a `KubeArmorConfig` object.
## KubeArmorConfig specification

```yaml
apiVersion: operator.kubearmor.com/v1
kind: KubeArmorConfig
metadata:
    labels:
        app.kubernetes.io/name: kubearmorconfig
        app.kubernetes.io/instance: kubearmorconfig-sample
        app.kubernetes.io/part-of: kubearmoroperator
        app.kubernetes.io/managed-by: kustomize
        app.kubernetes.io/created-by: kubearmoroperator
    name: [config name]
    namespace: [namespace name]
spec:
    # default global posture
    defaultCapabilitiesPosture: audit|block                    # DEFAULT - audit
    defaultFilePosture: audit|block                            # DEFAULT - audit
    defaultNetworkPosture: audit|block                         # DEFAULT - audit

    enableStdOutLogs: [show stdout logs for relay server]      # DEFAULT - false
    enableStdOutAlerts: [show stdout alerts for relay server]  # DEFAULT - false
    enableStdOutMsgs: [show stdout messages for relay server]  # DEFAULT - false 

    # default visibility configuration
    defaultVisibility: [comma separated: process|file|network] # DEFAULT - process,network

    # optionally drop the Resource field (full cmdline) from process visibility logs
    dropResourceFromProcessLogs: false                         # DEFAULT - false

    # enabling NRI
    # Naming convention for kubearmor daemonset in case of NRI will be effective only when initially NRI is available & enabled. 
    # In case snitch service account token is already present before its deployment, the naming convention won't show NRI, 
    # it will be based on the runtime present. This happens because operator won't get KubearmorConfig event(initially).
    enableNRI: [true|false] # DEFAULT - false

    # KubeArmor image and pull policy
    kubearmorImage:
        image: [image-repo:tag]                                # DEFAULT - kubearmor/kubearmor:stable
        imagePullPolicy: [image pull policy]                   # DEFAULT - Always

    # KubeArmor init image and pull policy
    kubearmorInitImage:
        image: [image-repo:tag]                                # DEFAULT - kubearmor/kubearmor-init:stable
        imagePullPolicy: [image pull policy]                   # DEFAULT - Always

    # KubeArmor relay image and pull policy
    kubearmorRelayImage:
        image: [image-repo:tag]                                # DEFAULT - kubearmor/kubearmor-relay-server:latest
        imagePullPolicy: [image pull policy]                   # DEFAULT - Always

    # KubeArmor controller image and pull policy
    kubearmorControllerImage:
        image: [image-repo:tag]                                # DEFAULT - kubearmor/kubearmor-controller:latest
        imagePullPolicy: [image pull policy]                   # DEFAULT - Always

    # kube-rbac-proxy image and pull policy
    kubeRbacProxyImage:
        image: [image-repo:tag]                                # DEFAULT - gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0
        imagePullPolicy: [image pull policy]                   # DEFAULT - Always

    # run the KubeArmor containers with their own seccomp profiles
    seccompEnabled: [true|false]                               # DEFAULT - false

    # port the kubearmor-controller webhook server listens on
    controllerPort: [port]                                     # DEFAULT - 9443
```

### Seccomp profiles for KubeArmor

`seccompEnabled` restricts the system calls available to KubeArmor's own containers. It does not apply seccomp to your workloads.

```yaml
spec:
  seccompEnabled: true
```

When it is `true`, the main container of the KubeArmor DaemonSet runs with the `Localhost` seccomp profile `kubearmor-seccomp.json`, and its init container, when deployed, with `kubearmor-init-seccomp.json`. Changing the value on a running `KubeArmorConfig` updates the existing DaemonSets, so the change rolls out to the KubeArmor pods.

**Prerequisites:** the profiles must exist on the node. The operator's snitch job writes them to `/var/lib/kubelet/seccomp` and labels the node `kubearmor.io/seccomp=yes` only if both files are present. On a node without that label, KubeArmor still runs, but without the profiles and without an error, even when `seccompEnabled` is `true`. To check a node:

```bash
kubectl get nodes -L kubearmor.io/seccomp
```

### Controller webhook port

`controllerPort` sets the port on which the `kubearmor-controller` webhook server listens. Change it when the default of `9443` is not usable in your cluster.

```yaml
spec:
  controllerPort: 8443
```

The operator passes the port to the controller as `webhook-port`, sets it as the container port, and points the `targetPort` of the `kubearmor-controller-webhook-service` Service at it. The Service itself keeps listening on port 443. Changing the value on a running `KubeArmorConfig` redeploys the controller with the new port.

**Prerequisites:** the Kubernetes API server must be able to reach the controller pods on this port, so any firewall rules between the control plane and the nodes must allow it.

A value of `0`, or leaving the field out, is ignored rather than treated as a reset. Removing `controllerPort` from a running `KubeArmorConfig` therefore keeps the current port; set it to `9443` explicitly to go back to the default.

## Verify if all the resources are up and running
If a valid configuration is received, the operator will deploy jobs to your nodes to get the environment information and then start installing KubeArmor components.

Once done, the following resources related to KubeArmor will exist in your cluster:
```
$ kubectl get all -n kubearmor -l kubearmor-app
NAME                                        READY   STATUS      RESTARTS   AGE
pod/kubearmor-operator-66fbff5559-qb7dh     1/1     Running     0          11m
pod/kubearmor-relay-557dfcc57b-c8t55        1/1     Running     0          2m53s
pod/kubearmor-controller-7879755b58-t4v8m   2/2     Running     0          2m53s
pod/kubearmor-snitch-lglbd-z92gb            0/1     Completed   0          31s
pod/kubearmor-bpf-docker-d4651-r5n7q        1/1     Running     0          30s

NAME                                           TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)     AGE
service/kubearmor-controller-metrics-service   ClusterIP   10.43.241.84    <none>        8443/TCP    2m53s
service/kubearmor                              ClusterIP   10.43.216.156   <none>        32767/TCP   2m53s

NAME                                        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR                                                                                                                                                                       AGE
daemonset.apps/kubearmor-bpf-docker-d4651   1         1         1       1            1           kubearmor.io/btf=yes,kubearmor.io/enforcer=bpf,kubearmor.io/runtime=docker,kubearmor.io/socket=run_docker.sock,kubernetes.io/os=linux   30s

NAME                                   READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/kubearmor-operator     1/1     1            1           11m
deployment.apps/kubearmor-relay        1/1     1            1           2m53s
deployment.apps/kubearmor-controller   1/1     1            1           2m53s

NAME                                              DESIRED   CURRENT   READY   AGE
replicaset.apps/kubearmor-operator-66fbff5559     1         1         1       11m
replicaset.apps/kubearmor-relay-557dfcc57b        1         1         1       2m53s
replicaset.apps/kubearmor-controller-7879755b58   1         1         1       2m53s

NAME                               COMPLETIONS   DURATION   AGE
job.batch/kubearmor-snitch-lglbd   1/1           3s         11m
```

## Uninstall the Operator

Uninstalling the Operator will also uninstall KubeArmor from all your nodes. To uninstall, just run:

```bash
helm uninstall kubearmor-operator -n kubearmor
```
