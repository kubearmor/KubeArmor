# Configuring KubeArmor via the `kubearmor-config` ConfigMap

Some KubeArmor settings can be configured at runtime using the `kubearmor-config` Kubernetes ConfigMap.

This page focuses on the `untrackedNs` setting, which controls namespaces that KubeArmor does not track.

## Configure untracked namespaces (`untrackedNs`)

KubeArmor reads the `untrackedNs` key from the `kubearmor-config` ConfigMap.

The `untrackedNs` value is a comma-separated list of namespace names.

Example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubearmor-config
data:
  untrackedNs: kube-system,kubearmor
```

### Apply changes at runtime

When the `untrackedNs` value changes, KubeArmor applies the updated list at runtime (without requiring a pod restart).

To update the value:

```bash
kubectl -n kubearmor edit configmap kubearmor-config
```

After saving the change, KubeArmor updates its runtime untracked namespace list.

### What `untrackedNs` affects

KubeArmor uses the untracked namespace list to:

- Skip enforcement for workloads in untracked namespaces (for example, policy enforcement is skipped when an endpoint namespace is in the untracked list).
- Skip updating namespace visibility based on ConfigMap defaults for namespaces in the untracked list.
- Skip emitting container visibility logs for workloads in untracked namespaces.

## Related documentation

- [Control Telemetry/Visibility](./kubearmor_visibility.md)
