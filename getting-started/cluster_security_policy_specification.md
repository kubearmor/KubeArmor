# Specification of Cluster Security Policy for Containers

## Cluster Policy Specification

Here is the specification of a Cluster security policy.

```text
apiVersion: security.kubearmor.com/v1
kind:KubeArmorClusterPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]              # --> optional

spec:
  severity: [1-10]                         # --> optional 
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  selector:
    matchExpressions:
      - key: [namespace|label]
        operator: [In|NotIn]
        values:
          - [namespaces|labels]

  process:
    matchPaths:
    - path: [absolute executable path]
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchPatterns:
    - pattern: [regex pattern]
      ownerOnly: [true|false]              # --> optional

  file:
    matchPaths:
    - path: [absolute file path]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
    matchPatterns:
    - pattern: [regex pattern]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional

  network:
    matchProtocols:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp]
      fromSource:                          # --> optional
      - path: [absolute exectuable path]

  capabilities:
    matchCapabilities:
    - capability: [capability name]
      fromSource:                          # --> optional
      - path: [absolute exectuable path]
  
  syscalls:
    matchSyscalls:
    - syscall:
      - syscallX
      - syscallY
      fromSource:                            # --> optional
      - path: [absolute exectuable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional
    matchPaths:
    - path: [absolute directory path | absolute exectuable path]
      recursive: [true|false]                # --> optional
      - syscall:
        - syscallX
        - syscallY
      fromSource:                            # --> optional
      - path: [absolute exectuable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional

  action: [Allow|Audit|Block] (Block by default)
```

> **Note** Please note that for system calls monitoring we only support audit action no matter what the value of action is

## Policy Spec Description

Now, we will briefly explain how to define a cluster security policy.

### Common

  A cluster security policy starts with the base information such as apiVersion, kind, and metadata. The apiVersion would be the same in any security policies. In the case of metadata, you need to specify the names of a policy and a namespace where you want to apply the policy and kind would be KubeArmorClusterPolicy.

  ```text
    apiVersion: security.kubearmor.com/v1
    kind:KubeArmorClusterPolicy
    metadata:
      name: [policy name]
      namespace: [namespace name]
  ```

### Severity

  The severity part is somewhat important. You can specify the severity of a given policy from 1 to 10. This severity will appear in alerts when policy violations happen.

  ```text
  severity: [1-10]
  ```

### Tags

  The tags part is optional. You can define multiple tags (e.g., WARNING, SENSITIVE, MITRE, STIG, etc.) to categorize security policies.

  ```text
  tags: ["tag1", ..., "tagN"]
  ```

### Message

  The message part is optional. You can add an alert message, and then the message will be presented in alert logs.

  ```text
  message: [message]
  ```

### Selector

  In the selector section for cluster-based policies, we use matchExpressions to define the namespaces where the policy should be applied and labels to select/deselect the workloads in those namespaces. Currently, only namespaces and labels can be matched, so the key should be 'namespace' and 'label'. The operator will determine whether the policy should apply to the namespaces and its workloads specified in the values field or not. Both `matchExpressions`, `namespace` and `label` are an ANDed operation.

  Operator: In
  When the operator is set to In, the policy will be applied only to the namespaces listed and if label `matchExpressions` is defined, the policy will be applied only to the workloads that match the labels in the values field.

  Operator: NotIn
  When the operator is set to NotIn, the policy will be applied to all other namespaces except those listed in the values field and if label `matchExpressions` is defined, the policy will be applied to all the workloads except that match the labels in the values field.

  ```text
    selector:
      matchExpressions:              
        - key: namespace
          operator: [In|NotIn]
          values:
          - [namespaces]
        - key: label
          operator: [In|NotIn]
          values:
          - [label]       # string format eg. -> (app=nginx)
  ```

  > **TIP** If the selector operator is omitted in the policy, it will be applied across all namespaces.

### Process

  In the process section, there are three types of matches: matchPaths, matchDirectories, and matchPatterns. You can define specific executables using matchPaths or all executables in specific directories using matchDirectories. In the case of matchPatterns, advanced operators may be able to determine particular patterns for executables by using regular expressions. However, the coverage of regular expressions is highly dependent on AppArmor \([Policy Core Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)\). Thus, we generally do not recommend using this match.

  ```text
    process:
      matchPaths:
      - path: [absolute executable path]
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional
        - path: [absolute executable path]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional
        - path: [absolute exectuable path]
      matchPatterns:
      - pattern: [regex pattern]
        ownerOnly: [true|false]            # --> optional
  ```

  In each match, there are three options.

  * ownerOnly \(static action: allow owner only; otherwise block all\)

    If this is enabled, the owners of the executable\(s\) defined with matchPaths and matchDirectories will be only allowed to execute.

  * recursive

    If this is enabled, the coverage will extend to the subdirectories of the directory defined with matchDirectories.

  * fromSource

    If a path is specified in fromSource, the executable at the path will be allowed/blocked to execute the executables defined with matchPaths or matchDirectories. For better understanding, let us say that an operator defines a policy as follows. Then, /bin/bash will be only allowed (blocked) to execute /bin/sleep. Otherwise, the execution of /bin/sleep will be blocked (allowed).

    ```text
      process:
        matchPaths:
        - path: /bin/sleep
          fromSource:
          - path: /bin/bash
    ```

### File

  The file section is quite similar to the process section.

  ```text
    file:
      matchPaths:
      - path: [absolute file path]
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional
        - path: [absolute file path]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional
        - path: [absolute file path]
      matchPatterns:
      - pattern: [regex pattern]
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
  ```

  The only difference between 'process' and 'file' is the readOnly option.

  * readOnly \(static action: allow to read only; otherwise block all\)

    If this is enabled, the read operation will be only allowed, and any other operations \(e.g., write\) will be blocked.  

### Network

  In the case of network, there is currently one match type: matchProtocols. You can define specific protocols among TCP, UDP, and ICMP.

  ```text
    network:
      matchProtocols:
      - protocol: [protocol]               # --> [ TCP | tcp | UDP | udp | ICMP | icmp ]
        fromSource:                        # --> optional
        - path: [absolute file path]
  ```

### Capabilities

  In the case of capabilities, there is currently one match type: matchCapabilities. You can define specific capability names to allow or block using matchCapabilities. You can check available capabilities in [Capability List](supported_capability_list.md).

  ```text
    capabilities:
      matchCapabilities:
      - capability: [capability name]
        fromSource:                        # --> optional
        - path: [absolute file path]
  ```

### Syscalls

  In the case of syscalls, there are two types of matches, matchSyscalls and matchPaths. matchPaths can be used to target system calls targeting specific binary path or anything under a specific directory, additionally you can slice based on syscalls generated by a binary or a group of binaries in a directory. You can use matchSyscall as a more general rule to match syscalls from all sources or from specific binaries.

```
syscalls:
  matchSyscalls:
  - syscall:
    - syscallX
    - syscallY
    fromSource:                            # --> optional
    - path: [absolute exectuable path]
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
  matchPaths:
  - path: [absolute directory path | absolute exectuable path]
    recursive: [true|false]                # --> optional
    - syscall:
      - syscallX
      - syscallY
    fromSource:                            # --> optional
    - path: [absolute exectuable path]
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
```

There is one options in each match.

  * fromSource

    If a path is specified in fromSource, kubearmor will match only syscalls generated by the defined source. For better undrestanding, lets take the example below. Only unlink system calls generated by `/bin/bash` will be matched.

    ```text
      process:
        matchPaths:
        - path: /bin/sleep
          - syscall:
            - unlink
          fromSource:
          - path: /bin/bash
    ```
  
  * recursive

    If this is enabled, the coverage will extend to the subdirectories of the directory.

* Action

  The action could be Allow, Audit, or Block. Security policies would be handled in a blacklist manner or a whitelist manner according to the action. Thus, you need to define the action carefully. You can refer to [Consideration in Policy Action](consideration_in_policy_action.md) for more details. In the case of the Audit action, we can use this action for policy verification before applying a security policy with the Block action.
  For System calls monitoring, we only support audit mode no matter what the action is set to.

  ```text
    action: [Allow|Audit|Block]
  ```
