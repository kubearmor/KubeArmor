# KubeArmor Self-Protection Policies

Zero-trust `KubeArmorPolicy` examples for KubeArmor's own production workloads. Closes [issue #2066](https://github.com/kubearmor/KubeArmor/issues/2066).

## Prerequisites

1. **PR1 merged** — [self-protection opt-in plumbing](https://github.com/kubearmor/KubeArmor/pulls) must be deployed. Block enforcement requires:
   - `kubearmor.io/self-protection: enabled` on infrastructure pod templates
   - `kubearmor-policy: enabled` (not `audited`)

2. **Enable self-protection** before block phase:

   **Direct Helm:**
   ```bash
   helm upgrade --install kubearmor ../../deployments/helm/KubeArmor \
     -n kubearmor --create-namespace \
     --set selfProtection.enabled=true
   ```

   **Operator (`KubeArmorConfig`):**
   ```yaml
   spec:
     selfProtectionEnabled: true
   ```

3. **karmor CLI** (optional, for discovery): [kubearmor-client](https://github.com/kubearmor/kubearmor-client)

## Two-phase workflow

| Phase | Namespace posture | Policies | Enforcement |
|-------|-------------------|----------|-------------|
| **Audit (dry-run)** | `namespace-posture-audit.yaml` | `audit/` | Violations logged; pods stay `audited` or opt-in with audit posture |
| **Block (zero-trust)** | `namespace-posture-block.yaml` | `block/` | Requires `selfProtection.enabled=true` |

Audit-phase policies are **intentionally permissive** (`dir: /` recursive allow) so you can observe real behavior via `karmor log` before tightening.

## Apply order

### Phase 1 — Audit

```bash
kubectl apply -f namespace-posture-audit.yaml
kubectl apply -f audit/
karmor log --namespace kubearmor
```

Restart workloads and watch logs during normal operation:

```bash
kubectl -n kubearmor rollout restart ds/kubearmor
kubectl -n kubearmor rollout restart deploy/kubearmor-relay
kubectl -n kubearmor rollout restart deploy/kubearmor-controller
```

Refine block-phase allow-lists from observed telemetry before phase 2.

### Phase 2 — Block

```bash
# Enable self-protection opt-in (requires PR1 merged)

# If installed via direct Helm chart:
helm upgrade --install kubearmor ../../deployments/helm/KubeArmor \
  -n kubearmor --create-namespace \
  --set selfProtection.enabled=true

# If installed via operator (no Helm release named "kubearmor"):
kubectl patch kubearmorconfig kubearmor-default -n kubearmor --type=merge \
  -p '{"spec":{"selfProtectionEnabled":true}}'
# Or edit KubeArmorConfig: spec.selfProtectionEnabled: true

kubectl apply -f namespace-posture-block.yaml
kubectl apply -f block/
```

Verify block enforcement:

```bash
POD=$(kubectl -n kubearmor get pod -l kubearmor-app=kubearmor -o name | head -1)
kubectl -n kubearmor exec -it "$POD" -c kubearmor -- /bin/bash -c 'echo test' || echo "blocked as expected"
karmor log --namespace kubearmor
```

Expect `Action: Block` (not `Audit (Block)`) when opt-in is active.

## Policy layout

This directory contains **13 YAML files**:

| Count | Files |
|-------|-------|
| 2 | `namespace-posture-audit.yaml`, `namespace-posture-block.yaml` |
| 5 | `audit/ksp-*.yaml` |
| 6 | `block/ksp-*.yaml` (includes admin-tools block for daemon main) |

**CRD note:** `matchDirectories[].dir` values must end with `/` (e.g. `/tmp/` not `/tmp`). Socket and single-file mounts use `file.matchPaths` instead.

## Policy index

| File | Target | Container filter |
|------|--------|------------------|
| `audit/ksp-kubearmor-daemon-main.yaml` | DaemonSet `kubearmor` | `[kubearmor]` |
| `audit/ksp-kubearmor-daemon-init.yaml` | DaemonSet init | `[init]` |
| `audit/ksp-kubearmor-relay.yaml` | Deployment `kubearmor-relay` | — |
| `audit/ksp-kubearmor-controller.yaml` | Deployment `kubearmor-controller` | — |
| `audit/ksp-kubearmor-operator.yaml` | Deployment `kubearmor-operator` | — |
| `block/ksp-kubearmor-daemon-main.yaml` | Daemon main allow-list | `[kubearmor]` |
| `block/ksp-kubearmor-daemon-init.yaml` | Init BPF compile allow-list | `[init]` |
| `block/ksp-kubearmor-daemon-admin-tools.yaml` | Block curl/bash in main only | `[kubearmor]` |
| `block/ksp-kubearmor-relay.yaml` | Relay allow-list | — |
| `block/ksp-kubearmor-controller.yaml` | Controller allow-list | — |
| `block/ksp-kubearmor-operator.yaml` | Operator allow-list | — |

## Container selector syntax

Use bracket syntax for per-container policies (KubeArmor policy convention, not a Kubernetes pod label):

```yaml
kubearmor.io/container.name: "[kubearmor]"
kubearmor.io/container.name: "[init]"
```

Plain `kubearmor` without brackets is parsed incorrectly.

## Environment notes

- **Runtime sockets:** Block policies include common CRI paths (`containerd`, `docker`, `crio`). Trim unused paths for your environment.
- **Network:** Block posture keeps `kubearmor-network-posture: audit` because the daemon uses `hostNetwork: true`.
- **Capabilities:** Daemon block policy allows required capabilities before `kubearmor-capabilities-posture: block`.
- **Out of scope:** `kubearmor-snitch` Job, BPF updater, kured — ephemeral or optional helpers.

## Rollback

```bash
kubectl delete -f block/ --ignore-not-found
kubectl delete -f audit/ --ignore-not-found
kubectl annotate namespace kubearmor \
  kubearmor-file-posture- \
  kubearmor-network-posture- \
  kubearmor-capabilities-posture- --overwrite

helm upgrade kubearmor ../../deployments/helm/KubeArmor \
  -n kubearmor --reuse-values --set selfProtection.enabled=false
```

## References

- [Least permissive access / zero trust](../getting-started/least_permissive_access.md)
- [Default posture](../getting-started/default_posture.md)
- [Security policy examples](../getting-started/security_policy_examples.md)
