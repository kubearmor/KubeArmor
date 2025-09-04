# Install KubeArmor on GKE Autopilot

GKE autopilot by default restrict the workloads that requires advance permissions/capabilities i.e. `hostPath` mounts, capabilities like `SYS_ADMIN`, etc. User can deploy such applications/workloads using a feature called Workload Allowlist.

KubeArmor maintains Allowlist for every stable release as part of [GKE partner workloads](https://cloud.google.com/kubernetes-engine/docs/how-to/run-autopilot-partner-workloads). Users can use the allowlist to deploy KubeArmor on their GKE cluster.

### 1. ⬇️ Pull KubeArmor Allowlist 

Apply the following yaml to sync kubearmor allowlist from GKE partner repository

```
# kubearmor-allowlist.yaml
apiVersion: auto.gke.io/v1
kind: AllowlistSynchronizer
metadata:
  name: kubearmor-allow-list
spec:
  allowlistPaths:
  - Accuknox/kubearmor/*

```
verify that kubearmor allowlist(s) are synchronized

```
kubectl get WorkloadAllowlist
```

### 2. 🚀 Deploy KubeArmor using Helm Chart

```
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor kubearmor/kubearmor \
  --set environment.name=autopilot \
  -n kubearmor --create-namespace
```

### 3. 🎉 Verify KubeArmor is running

```
kubectl get pods -n kubearmor
```