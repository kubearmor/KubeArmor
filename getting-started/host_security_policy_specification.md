# Specification of Host Security Policy for Nodes/VMs

## Policy Specification

Here is the specification of a host security policy.

```text
apiVersion: security.kubearmor.com/v1
kind:KubeArmorHostPolicy
metadata:
  name: [policy name]

spec:
  severity: [1-10]                         # --> optional 
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  nodeSelector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

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
      fromSource:
      - path: [absolute exectuable path]

  capabilities:
    matchCapabilities:
    - capability: [capability name]
      fromSource:
      - path: [absolute exectuable path]

  action: [Audit|Block] (Block by default)
```

> **Note** Please note that for system calls monitoring we only support audit action no matter what the value of action is

For better understanding, you can check [the KubeArmorHostPolicy spec diagram](../.gitbook/assets/kubearmorhostpolicy-spec-diagram.pdf).

## Policy Spec Description

Now, we will briefly explain how to define a host security policy.

* Common

  A security policy starts with the base information such as apiVersion, kind, and metadata. The apiVersion and kind would be the same in any security policies. In the case of metadata, you need to specify the name of a policy.

  ```text
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorHostPolicy
    metadata:
      name: [policy name]
  ```

  Make sure that you need to use `KubeArmorHostPolicy`, not `KubeArmorPolicy`.

* Severity

  You can specify the severity of a given policy from 1 to 10. This severity will appear in alerts when policy violations happen.

  ```text
  severity: [1-10]
  ```

* Tags

  The tags part is optional. You can define multiple tags (e.g., WARNING, SENSITIVE, MITRE, STIG, etc.) to categorize security policies.

  ```text
  tags: ["tag1", ..., "tagN"]
  ```

* Message

  The message part is optional. You can add an alert message, and then the message will be presented in alert logs.

  ```text
  message: [message]
  ```

* NodeSelector

  The node selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify \(a group of\) nodes based on labels.

  ```text
    nodeSelector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
  ```

  If you do not have any custom labels, you can use system labels as well.

  ```text
      kubernetes.io/arch: [architecture, (e.g., amd64)]
      kubernetes.io/hostname: [host name, (e.g., kubearmor-dev)]
      kubernetes.io/os: [operating system, (e.g., linux)]
  ```

* Process

  In the process section, there are three types of matches: matchPaths, matchDirectories, and matchPatterns. You can define specific executables using matchPaths or all executables in specific directories using matchDirectories. In the case of matchPatterns, advanced operators may be able to determine particular patterns for executables by using regular expressions. However, we generally do not recommend using this match.

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

* File

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

* Network

  In the case of network, there is currently one match type: matchProtocols. You can define specific protocols among TCP, UDP, and ICMP.

  ```text
    network:
      matchProtocols:
      - protocol: [protocol(,)]            # --> [ TCP | tcp | UDP | udp | ICMP | icmp ]
        fromSource:
        - path: [absolute file path]
  ```

* Capabilities

  In the case of capabilities, there is currently one match type: matchCapabilities. You can define specific capability names to allow or block using matchCapabilities. You can check available capabilities in [Capability List](supported_capability_list.md).

  ```text
    capabilities:
      matchCapabilities:
      - capability: [capability name(,)]
        fromSource:
        - path: [absolute file path]
  ```
* Syscalls

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

  The action could be Audit or Block in general. In order to use the Allow action, you should define 'fromSource'; otherwise, all Allow actions will be ignored by default.

  ```text
    action: [Audit|Block]
  ```

  If 'fromSource' is defined, we can use all actions for specific rules.

  ```text
    action: [Allow|Audit|Block]
  ```
  For System calls monitoring, we only support audit mode no matter what the action is set to.
  
