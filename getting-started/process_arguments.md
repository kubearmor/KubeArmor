# Process Argument Matching

KubeArmor provides the ability to enforce security policies based on process arguments, offering finer granularity in rule definitions.

## Overview

Process argument matching lets a policy constrain a process execution by listing allowed process arguments for a specific `process.matchPaths[].path`.

This is configured by the `matchArgs` setting and expressed in policies using `allowedArgs`.

## Prerequisites

- A running KubeArmor deployment.
- Permission to update KubeArmor’s configuration (for example, ConfigMap/DaemonSet arguments).

## Enabling/Disabling process argument matching

Argument matching is controlled by the `matchArgs` configuration key.

- **Enable:** set `matchArgs=true`
- **Disable:** set `matchArgs=false`

KubeArmor also exposes this setting as a command-line flag:

- `-matchArgs` (default: `true`)

## Writing a policy with `allowedArgs`

Use `allowedArgs` under a `process.matchPaths` entry to list which arguments are allowed for that path.

### Sample policy

**Scenario:** Allow `/usr/bin/python3.6` to execute only if it is accompanied by the arguments `-m` and `random`.

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-ubuntu-1-allow-proc-args
  namespace: multiubuntu
spec:
  severity: 5
  message: "Block all arguments except allowedArgs"
  selector:
    matchLabels:
      container: ubuntu-1
  process:
    matchPaths:
    - path: /usr/bin/python3.6
      allowedArgs:
      - -m
      - random
  action:
    Block
```

## Limitations

1. **Argument count:** a maximum of **20 arguments** per process are supported for a specific path.
2. **Character limit:** the maximum length for a single argument is **104 characters**.

## Troubleshooting

### `allowedArgs` does not seem to be applied

1. Confirm argument matching is enabled with `matchArgs=true` (or `-matchArgs=true`).
2. Confirm `allowedArgs` is specified under a `process.matchPaths` entry.

## Related documentation

- [Security policy specification](./security_policy_specification.md)
