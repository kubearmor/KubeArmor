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
| global.autoDeploy | bool | false | controls whether the operator auto-creates a KubeArmorConfig CR with default settings |
| global.imagePinning | bool | false | controls whether the operator uses pinned images defined under global.kubearmor.images |
| global.registry.secretName | string | "" | optional image pull secret name used when kubearmorOperator.image.imagePullSecrets is not set |
| global.kubearmor.repo | string | kubearmor | base image repository for all pinned KubeArmor images |
| global.kubearmor.images.kubearmor.image | string | kubearmor | image name for the KubeArmor core daemon |
| global.kubearmor.images.kubearmor.tag | string | stable | tag for the KubeArmor core daemon image |
| global.kubearmor.images.kubearmorInit.image | string | kubearmor-init | image name for the KubeArmor init container |
| global.kubearmor.images.kubearmorInit.tag | string | stable | tag for the KubeArmor init container image |
| global.kubearmor.images.kubearmorRelay.image | string | kubearmor-relay-server | image name for the KubeArmor relay server |
| global.kubearmor.images.kubearmorRelay.tag | string | latest | tag for the KubeArmor relay server image |
| global.kubearmor.images.kubearmorController.image | string | kubearmor-controller | image name for the KubeArmor controller |
| global.kubearmor.images.kubearmorController.tag | string | latest | tag for the KubeArmor controller image |
| global.kubearmor.images.kubearmorSnitch.image | string | kubearmor-snitch | image name for the KubeArmor snitch job |
| global.kubearmor.images.kubearmorSnitch.tag | string | latest | tag for the KubeArmor snitch job image |
| global.kubearmor.images.kubearmorOperator.image | string | kubearmor-operator | image name for the KubeArmor operator when imagePinning is enabled |
| global.kubearmor.images.kubearmorOperator.tag | string | latest | tag for the KubeArmor operator image when imagePinning is enabled |
| kubearmorOperator.enableOCIHooks | bool | false | enables OCI hooks integration by setting the KUBEARMOR_OCI_HOOKS environment variable in the operator pod |
| kubearmorOperator.annotateResource | bool | false | passes --annotateResource flag to the operator to control RBAC-related behavior |
| kubearmorOperator.annotateExisting | bool | false | passes --annotateExisting flag to the operator to control behavior on existing resources |
| kubearmorOperator.name | string | kubearmor-operator | name of the operator Deployment and ServiceAccount |
| kubearmorOperator.image.repository | string | docker.io/kubearmor/kubearmor-operator | image repository to pull KubeArmorOperator from when imagePinning is disabled |
| kubearmorOperator.image.tag | string | "" | explicit tag for the operator image; when empty, the chart version is used as the tag |
| kubearmorOperator.image.imagePullSecrets | list | [] | list of image pull secrets for the operator pod; also forwarded to the operator via --image-pull-secrets |
| kubearmorOperator.imagePullPolicy | string | IfNotPresent | pull policy for the operator image |
| kubearmorOperator.args | list | [] | additional arguments appended to the operator container command |
| kubearmorOperator.tolerations | list | [] | pod tolerations applied to the operator Deployment |
| kubearmorOperator.resources | object | {} | operator container resource requests and limits |
| kubearmorOperator.podLabels | object | {} | additional labels applied to the operator pod template |
| kubearmorOperator.podAnnotations | object | {} | additional annotations applied to the operator pod template |
| kubearmorOperator.podSecurityContext | object | {} | pod-level security context for the operator Deployment |
| kubearmorOperator.securityContext | object | {} | container-level security context for the operator container |
| kubearmorOperator.env | list | [] | additional environment variables injected into the operator container |
| kubearmorOperator.nodeSelector | object | {} | node selector for scheduling the operator pod |
| kubearmorConfig.defaultCapabilitiesPosture | string | audit | default capabilities posture in the generated KubeArmorConfig |
| kubearmorConfig.defaultFilePosture | string | audit | default file posture in the generated KubeArmorConfig |
| kubearmorConfig.defaultNetworkPosture | string | audit | default network posture in the generated KubeArmorConfig |
| kubearmorConfig.defaultVisibility | string | process,network | default visibility levels enabled in the generated KubeArmorConfig |
| kubearmorConfig.enableStdOutLogs | bool | false | enables stdout logs for the relay server in the generated KubeArmorConfig |
| kubearmorConfig.enableStdOutAlerts | bool | false | enables stdout alerts for the relay server in the generated KubeArmorConfig |
| kubearmorConfig.enableStdOutMsgs | bool | false | enables stdout messages for the relay server in the generated KubeArmorConfig |
| kubearmorConfig.seccompEnabled | bool | false | enables seccomp support in the generated KubeArmorConfig |
| kubearmorConfig.alertThrottling | bool | true | enables alert throttling in the generated KubeArmorConfig |
| kubearmorConfig.maxAlertPerSec | int | 10 | maximum number of alerts per second when throttling is enabled |
| kubearmorConfig.throttleSec | int | 30 | throttling window in seconds when alertThrottling is enabled |
| tlsSecrets.kubearmorCa | string | kubearmor-ca | name of the TLS secret that stores the KubeArmor CA certificate |
| tlsSecrets.kubearmorClient | string | kubearmor-client-certs | name of the TLS secret that stores KubeArmor client certificates |
| tlsSecrets.relayServer | string | kubearmor-relay-server-certs | name of the TLS secret for the relay server |
| tlsSecrets.controllerWebhook | string | kubearmor-controller-webhook-server-cert | name of the TLS secret for the controller webhook server |

The operator needs a `KubeArmorConfig` object in order to create resources related to KubeArmor. A default config is present in Helm `values.yaml` which can be overridden during Helm install. To install KubeArmor with default configuration use `--set global.autoDeploy=true` flag with helm install/upgrade command. It is possible to specify configuration even after KubeArmor resources have been installed by directly editing the created `KubeArmorConfig` CR.

By default, the chart does not deploy the default KubeArmorConfig CR. After installation, the operator waits for the user to create a `KubeArmorConfig` object unless `global.autoDeploy` is set to `true`.

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

    # enabling NRI
    # Naming convention for kubearmor daemonset in case of NRI will be effective only when initally NRI is available & enabled. 
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
```

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
