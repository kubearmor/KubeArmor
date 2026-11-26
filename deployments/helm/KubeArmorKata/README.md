# KubeArmor Kata Sidecar Helm Chart

Deploys KubeArmor as a sidecar (plus RBAC and `ServiceAccount` prerequisites) inside Kata Containers Pods.

For architecture details, guest kernel/OCI hook prerequisites, end-to-end testing, log aggregation, and Confidential Containers (CoCo) notes, see [pkg/KubeArmorOperator/hook/README.md](../../../pkg/KubeArmorOperator/hook/README.md).

## Quick Start

Install with the bundled sample `nginx` + `kubearmor` Kata Pod:

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace
```

Install with a locally built image (`kata-test`):

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace \
  --set runtimeClassName=kata-qemu \
  --set kubearmor.image.tag=kata-test \
  --set kubearmor.image.pullPolicy=Never
```

Install RBAC and `ServiceAccount` prerequisites only (when adding the `kubearmor` sidecar to your own manifests):

```bash
helm install kubearmor-kata ./deployments/helm/KubeArmorKata \
  --namespace kubearmor --create-namespace \
  --set sampleWorkload.enabled=false
```

## Configuration

| Key | Default | Description |
| :--- | :--- | :--- |
| `runtimeClassName` | `kata-qemu` | `RuntimeClass` installed on the cluster. |
| `serviceAccount.create` | `true` | Create the `ServiceAccount` for Kata Pods. |
| `serviceAccount.name` | `""` | Override the `ServiceAccount` name (defaults to release fullname). |
| `rbac.create` | `true` | Create the `ClusterRole` and `ClusterRoleBinding`. |
| `initContainer.image.repository` | `docker.io/kubearmor/kubearmor-init` | Init container image repository. |
| `initContainer.image.tag` | `stable` | Init container image tag. |
| `initContainer.image.pullPolicy` | `IfNotPresent` | Init container image pull policy. |
| `kubearmor.image.repository` | `docker.io/kubearmor/kubearmor` | KubeArmor sidecar image repository. |
| `kubearmor.image.tag` | `stable` | KubeArmor sidecar image tag. |
| `kubearmor.image.pullPolicy` | `IfNotPresent` | KubeArmor sidecar image pull policy. |
| `kubearmor.args` | `["-untrackedNs=", "-useOCIHooks=true", "-hookFilePath=/opt/kubearmor_hook_output.json"]` | Arguments passed to the `kubearmor` sidecar. |
| `kubearmor.grpcPort` | `32767` | gRPC log/alert server port. |
| `kubearmor.healthPort` | `32766` | gRPC health probe port. |
| `sampleWorkload.enabled` | `true` | Deploy the sample `nginx` + `kubearmor` Kata `Deployment`. |
| `sampleWorkload.replicas` | `1` | Replicas for the sample `Deployment`. |
| `sampleWorkload.name` | `nginx` | Name of the sample workload container. |
| `sampleWorkload.image.repository` | `nginx` | Sample workload image repository. |
| `sampleWorkload.image.tag` | `latest` | Sample workload image tag. |
| `sampleWorkload.image.pullPolicy` | `IfNotPresent` | Sample workload image pull policy. |
| `sampleWorkload.port` | `80` | Sample workload container port. |
| `terminationGracePeriodSeconds` | `60` | Pod termination grace period. |
| `nodeSelector` | `katacontainers.io/kata-runtime: "true"`, `kubernetes.io/os: linux` | Node selector for Kata-enabled Linux nodes. |
| `tolerations` | `[]` | Pod tolerations. |

