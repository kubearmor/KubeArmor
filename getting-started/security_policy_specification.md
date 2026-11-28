# Specification of Security Policy for Containers

## Policy Specification

Here is the specification of a security policy.

```text
apiVersion: security.kubearmor.com/v1
kind:KubeArmorPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]

spec:
  severity: [1-10]                         # --> optional 
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  selector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]
    matchExpressions:
      - key: [label]
        operator: [In|NotIn]
        values:
          - [labels]

  process:
    matchPaths:
    - path: [absolute executable path]
      ownerOnly: [true|false]              # --> optional
      execname: [binary name]              # --> optional
      pts: [true|false]                    # --> optional
      fromSource:                          # --> optional
      - path: [absolute executable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      ownerOnly: [true|false]              # --> optional
      pts: [true|false]                    # --> optional
      fromSource:                          # --> optional
      - path: [absolute executable path]
    matchPatterns:
    - pattern: [regex pattern]
      ownerOnly: [true|false]              # --> optional

  file:
    matchPaths:
    - path: [absolute file path]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      pts: [true|false]                    # --> optional
      fromSource:                          # --> optional
      - path: [absolute executable path]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional
      pts: [true|false]                    # --> optional
      fromSource:                          # --> optional
      - path: [absolute executable path]
    matchPatterns:
    - pattern: [regex pattern]
      readOnly: [true|false]               # --> optional
      ownerOnly: [true|false]              # --> optional

  network:
    matchProtocols:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp]
      pts: [true|false]                    # --> optional
      fromSource:                          # --> optional
      - path: [absolute executable path]

  capabilities:
    matchCapabilities:
    - capability: [capability name]
      fromSource:                          # --> optional
      - path: [absolute executable path]
  
  syscalls:
    matchSyscalls:
    - syscall:
      - syscallX
      - syscallY
      fromSource:                            # --> optional
      - path: [absolute executable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional
    matchPaths:
    - path: [absolute directory path | absolute executable path]
      recursive: [true|false]                # --> optional
      - syscall:
        - syscallX
        - syscallY
      fromSource:                            # --> optional
      - path: [absolute executable path]
      - dir: [absolute directory path]
        recursive: [true|false]              # --> optional

  presets:
  - name: [preset name]
    action: [Audit|Block]                  # --> optional

  action: [Allow|Audit|Block] (Block by default)
```

> **Note** Please note that for system calls monitoring we only support audit action no matter what the value of action is

For better understanding, you can check [the KubeArmorPolicy spec diagram](../.gitbook/assets/kubearmorpolicy-spec-diagram.pdf).

## Policy Spec Description

Now, we will briefly explain how to define a security policy.

### Common

  A security policy starts with the base information such as apiVersion, kind, and metadata. The apiVersion and kind would be the same in any security policies. In the case of metadata, you need to specify the names of a policy and a namespace where you want to apply the policy.

  ```text
    apiVersion: security.kubearmor.com/v1
    kind:KubeArmorPolicy
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

### Per-rule Overrides

  `severity`, `tags`, `message` and `action` are not limited to the top of the spec. The same fields can be set on a match section (`process`, `file`, `network`, `capabilities`) and on each individual match rule inside it, which allows a single policy to raise alerts with different severities and messages. The `syscalls` section is the one exception: it accepts `severity`, `tags` and `message`, but not `action`, because syscall rules are always audit-only. Each field is resolved independently, using the most specific value that is set:

  1. the value set on the individual match rule (for example `spec.process.matchPaths[0].severity`)
  2. the value set on the match section (for example `spec.process.severity`)
  3. the value set on the policy itself (for example `spec.severity`)

  `tags` is a whole-value override: the most specific non-empty `tags` list replaces the outer list, and the lists are not merged.

  ```yaml
  apiVersion: security.kubearmor.com/v1
  kind: KubeArmorPolicy
  metadata:
    name: per-rule-overrides
    namespace: default
  spec:
    selector:
      matchLabels:
        app: nginx
    severity: 1
    tags: ["POLICY"]
    action: Block
    process:
      severity: 2
      tags: ["PROCESS"]
      action: Block
      matchPaths:
      - path: /bin/ls
        severity: 5
        tags: ["SENSITIVE"]
        message: "ls was executed"
        action: Audit
      - path: /bin/cat
        message: "cat was executed"
      - path: /bin/rm
        message: "rm was executed"
    file:
      severity: 4
      matchPaths:
      - path: /etc/shadow
        message: "shadow was read"
  ```

  In the example, the `/bin/ls` rule sets `action: Audit`, so it overrides the `Block` action inherited from the `process` section and the policy, while `/bin/cat` and `/bin/rm` remain blocked. The `tags: ["SENSITIVE"]` on `/bin/ls` also replaces the `PROCESS` tags from the section, so that alert carries `SENSITIVE` alone; tags are replaced as a whole and are not merged. `/bin/cat` and `/bin/rm` inherit severity 2 and the `PROCESS` tag from the `process` section. The `/etc/shadow` rule inherits severity 4 from the `file` section and falls back to the policy-level `Block` action and `POLICY` tag.

  > **NOTE** Write `action` in its capitalized form (`Allow`, `Audit` or `Block`) everywhere, at the policy level as well as below it. A `KubeArmorPolicy` or `KubeArmorClusterPolicy` is validated against the CRD's OpenAPI schema before KubeArmor's Go code ever sees it, and that schema accepts only `Allow`, `Audit` and `Block`. The lowercase aliases (`allow`, `audit`, `block`) are accepted only for the policy-level `action`, and only in non-Kubernetes (VM/bare-metal) mode, where KubeArmor normalizes them into the capitalized form.

### Selector

#### MatchLabels

  The selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify \(a group of\) pods based on labels.

  ```text
    selector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
  ```

  #### MatchExpressions
  Further in selector we can use `matchExpressions` to define labels to select/deselect the workloads. Currently, only labels can be matched, so the key should be 'label'. The operator will determine whether the policy should apply to the workloads specified in the values field or not.

  Operator: In
  When the operator is set to In, the policy will be applied only to the workloads that match the labels in the values field.

  Operator: NotIn
  When the operator is set to NotIn, the policy will be applied to all the workloads except that match the labels in the values field.

  ```text
    selector:
      matchExpressions:              
        - key: label
          operator: [In|NotIn]
          values:
          - [label]       # string format eg. -> (app=nginx)
  ```
  > **NOTE** Both `matchExpressions` and `matchLabel` are an ANDed operation.

### Process

  In the process section, there are three types of matches: matchPaths, matchDirectories, and matchPatterns. You can define specific executables using matchPaths or all executables in specific directories using matchDirectories. In the case of matchPatterns, advanced operators may be able to determine particular patterns for executables by using regular expressions. However, the coverage of regular expressions is highly dependent on AppArmor \([Policy Core Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)\). Thus, we generally do not recommend using this match.

  ```text
    process:
      matchPaths:
      - path: [absolute executable path]
        ownerOnly: [true|false]            # --> optional
        execname: [binary name]            # --> optional
        pts: [true|false]                  # --> optional
        fromSource:                        # --> optional
        - path: [absolute executable path]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        ownerOnly: [true|false]            # --> optional
        pts: [true|false]                  # --> optional
        fromSource:                        # --> optional
        - path: [absolute executable path]
      matchPatterns:
      - pattern: [regex pattern]
        ownerOnly: [true|false]            # --> optional
  ```

  In each match, there are the following options.

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

  * execname

    Besides an absolute path, matchPaths can select executables by their binary name using execname. The value is a binary name only, without any directory separator (e.g., sleep), and it matches the execution of any binary with that name, regardless of the directory it resides in. When execname is set, it takes precedence over path in the same matchPaths entry. A value that contains a `/` (for example `/bin/sleep` or `sbin/sleep`) is rejected by the CRD's OpenAPI schema, which allows only characters other than `/` in this field, so the policy is refused at admission time before KubeArmor ever sees it.
  * pts

    The pts option scopes a rule to actions that originate from a pseudo-terminal (TTY), such as commands entered in an interactive shell. If pts is set to false, only actions performed by processes that have a pseudo-terminal attached are matched; actions without an attached TTY (e.g., processes started directly by a container runtime or a system daemon) are not matched. If pts is set to true or omitted, the rule applies regardless of whether a pseudo-terminal is attached. Only the BPF-LSM enforcer implements `pts`: the AppArmor and SELinux enforcers ignore it, so on a host using either of those LSMs the rule applies to every matching action, whether or not a pseudo-terminal is attached.

    ```text
      process:
        matchPaths:
        - execname: apt
        - path: /bin/sleep
          pts: false
    ```

### File

  The file section is quite similar to the process section.

  ```text
    file:
      matchPaths:
      - path: [absolute file path]
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        pts: [true|false]                  # --> optional
        fromSource:                        # --> optional
        - path: [absolute file path]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        pts: [true|false]                  # --> optional
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

  * pts

    As with process executions, pts: false scopes the file rule to operations performed by processes that have a pseudo-terminal attached. Only the BPF-LSM enforcer implements `pts`: the AppArmor and SELinux enforcers ignore it, so on a host using either of those LSMs the rule applies to every matching action, whether or not a pseudo-terminal is attached.

### Network

  In the case of network, there is currently one match type: matchProtocols. You can define specific protocols among TCP, UDP, and ICMP.

  ```text
    network:
      matchProtocols:
      - protocol: [protocol]               # --> [ TCP | tcp | UDP | udp | ICMP | icmp ]
        pts: [true|false]                  # --> optional
        fromSource:                        # --> optional
        - path: [absolute file path]
  ```

  * pts

    As with process executions, pts: false scopes the protocol rule to connections made by processes that have a pseudo-terminal attached. Only the BPF-LSM enforcer implements `pts`: the AppArmor and SELinux enforcers ignore it, so on a host using either of those LSMs the rule applies to every matching action, whether or not a pseudo-terminal is attached.

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
    - path: [absolute executable path]
    - dir: [absolute directory path]
      recursive: [true|false]              # --> optional
  matchPaths:
  - path: [absolute directory path | absolute executable path]
    recursive: [true|false]                # --> optional
    - syscall:
      - syscallX
      - syscallY
    fromSource:                            # --> optional
    - path: [absolute executable path]
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

### Presets

  The presets section is optional. A preset is a hardening rule that KubeArmor enforces from its BPF LSM programs directly, so the behavior does not have to be described with process, file, or syscalls matches: a preset is selected by name and given an action.

  ```text
    presets:
    - name: [preset name]                    # --> anonymousMapExec | filelessExec | protectEnv | exec | protectProc
      action: [Audit|Block]                  # --> optional (Block by default)
  ```

  One policy can declare several presets, and presets can be combined with the other sections of the same policy.

  ```yaml
  apiVersion: security.kubearmor.com/v1
  kind: KubeArmorPolicy
  metadata:
    name: ksp-presets
    namespace: multiubuntu
  spec:
    selector:
      matchLabels:
        group: group-1
    presets:
    - name: protectEnv
      action: Block
    - name: filelessExec
      action: Audit
    severity: 5
    message: "preset rule is violated"
  ```

  The supported presets are the following.

  | Preset | Restriction | BPF LSM hook |
  | --- | --- | --- |
  | `anonymousMapExec` | Rejects anonymous (not file-backed) memory mappings that request the execute permission, covering both the mapping and the protection change | `mmap_file`, `file_mprotect` |
  | `filelessExec` | Rejects the execution of binaries stored in `memfd`, `/dev/shm/`, or `/run/shm/` | `bprm_check_security` |
  | `protectEnv` | Rejects opening `/proc/[pid]/environ` of a process other than the caller | `file_open` |
  | `exec` | Reports or rejects executions started by a process that has a terminal attached, which targets interactive shells | `bprm_check_security` |
  | `protectProc` | Rejects accessing `/proc/[pid]/` entries of a process other than the caller | `file_open` |

  Things to keep in mind when using presets.

  * Presets require the BPFLSM enforcer. When a node runs with the AppArmor or the SELinux enforcer, the preset programs are not registered and the presets of a policy have no effect, while the other sections of the same policy are still applied.

  * The action is defined per preset. It defaults to Block and only `Audit` switches a preset to report-only mode; `Allow` is accepted by the CRD but handled as `Block`.

  * Presets apply to the containers of the workloads selected by `selector` on which policy enforcement is enabled, in the same way as the other rules of a policy.

  * Alerts generated by a preset carry the policy name, severity, tags, and message of the policy that declares it, and their enforcer field is prefixed with `PRESET-` (for example `PRESET-ProtectEnvPreset`).

  * Preset names are case-sensitive. A misspelled or unsupported name is ignored without an error; the policy is still accepted by the API server.
