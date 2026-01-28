# Process Argument Matching

KubeArmor provides the ability to enforce security policies based on process arguments, offering finer granularity in rule definitions. This guide demonstrates how to enable this feature and define policies to utilize it.

## Enabling/Disabling Process Argument Matching

To enable or disable this feature, you must modify the KubeArmor configuration (typically within the KubeArmor ConfigMap or DaemonSet arguments).

* **Enable:** Add `matchArgs=true`
* **Disable:** Remove the flag or set `matchArgs=false`

### Limitations

Please note the following constraints when using Process Argument Matching:

1. **Argument Count:** A maximum of **20 arguments** per process are supported for a specific path.
2. **Character Limit:** The maximum length for a single argument is **104 characters**.
3. **Enforcement Behavior:** When `matchArgs` is enabled, if the enforcer encounters an argument exceeding the 104-character limit, the execution will be **blocked by default** for security reasons.

### Sample Policy

The following policy demonstrates how to allow specific arguments for a process while blocking others.

**Scenario:** Allow `/usr/bin/python3.6` to execute only if it is accompanied by the arguments `-m` and `random`.

```yaml
apiVersion: [security.kubearmor.com/v1](https://security.kubearmor.com/v1)
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

## Policy violation alert

If a process is executed with arguments that do not match the policy, a policy violation alert is generated.

When the enforcer reports a process exec event (`lsm=SECURITY_BPRM_CHECK`), the log fields are populated as follows:

- `ProcessName` is set from the event's process path.
- `Source` is set from the event's parent/source process.
- `Resource` contains the original `Source` value produced by the base log builder, and falls back to `ProcessName` when empty.

The following is an example alert:

```json
{
  "Timestamp": 1765863439,
  "UpdatedTime": "2025-12-16T05:37:19.127331Z",
  "ClusterName": "default",
  "HostName": "aryan",
  "NamespaceName": "multiubuntu",
  "Owner": {
    "Ref": "Deployment",
    "Name": "ubuntu-1-deployment",
    "Namespace": "multiubuntu"
  },
  "PodName": "ubuntu-1-deployment-8dc5d8d48-5s8pf",
  "Labels": "group=group-1,container=ubuntu-1",
  "ContainerID": "4771ac3e9074f1bf8b01038d0cf776960aa44b18edccc0f2b017e8465dedefcd",
  "ContainerName": "ubuntu-1-container",
  "ContainerImage": "docker.io/kubearmor/ubuntu-w-utils:latest@sha256:8c94d921d36698a63e02337302989e8311169b750cc0dd4713e688f3631ab4ba",
  "HostPPID": 190507,
  "HostPID": 191949,
  "PPID": 190507,
  "PID": 113,
  "UID": 0,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/usr/bin/python3.6",
  "PolicyName": "ksp-ubuntu-1-allow-proc-args",
  "Severity": "5",
  "Message": "block all arguments except allowedArgs",
  "Type": "MatchedPolicy",
  "Source": "/bin/bash",
  "Operation": "Process",
  "Resource": "/usr/bin/python3.6 -m pydoc",
  "Data": "lsm=SECURITY_BPRM_CHECK",
  "EventData": {
    "Lsm": "SECURITY_BPRM_CHECK"
  },
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Permission denied",
  "Cwd": "/",
  "TTY": "pts0",
  "ExecEvent": {
    "ExecID": "824416229130095",
    "ExecutableName": "bash"
  },
  "KubeArmorVersion": "v1.6.5-8-g3d55b346-dirty"
}
```
