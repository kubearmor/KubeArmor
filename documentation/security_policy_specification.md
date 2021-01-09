# Security Policy Specification

Here is the specification of a security policy.

```
apiVersion: security.accuknox.com/v1
kind:KubeArmorPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]

spec:
  selector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

  process:
    matchPaths:
    - path: [absolute executable path]
      ownerOnly: [true|false]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]
      ownerOnly: [true|false]
    matchPatterns:
    - pattern: [regex pattern]
      ownerOnly: [true|false]

  file:
    matchPaths:
    - path: [absolute file path]
      readOnly: [true|false]
      ownerOnly: [true|false]
    matchDirectories:
    - dir: [absolute directory path]
      recursive: [true|false]
      readOnly: [true|false]
      ownerOnly: [true|false]
    matchPatterns:
    - pattern: [regex pattern]
      readOnly: [true|false]
      ownerOnly: [true|false]

  capabilities:
    matchCapabilities:
    - [capability name]
    matchOperations:
    - [operation name]

  action: [Block|Allow|Audit]
```

# Policy Spec Description

Now, we will briefly explain how to define a security policy.

- Base

    A security policy starts with base information such as apiVersion, kind, and metadata. The apiVersion and kind would be the same in any security policies. In the case of metadata, you need to specify the names of a policy and a namespace where you wnat to apply the policy.

    ```
    apiVersion: security.accuknox.com/v1
    kind:KubeArmorPolicy
    metadata:
      name: [policy name]
      namespace: [namespace name]
    ```

- Selector

    The selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify target pods or a group of pods based on labels.
    
    ```
    selector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
     ```

- Process

    In the process section, there are three types of matches: matchPaths, matchDirectories, and matchPatterns. You can define specific executables using matchPaths or all executables in specific directories using matchDirectories. In the case of matchPatterns, advanced operators may be able to determine particular patterns for executables by using regular expressions. However, the coverage of regular expressions is highly dependent on AppArmor ([Policy Core Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)). Thus, we generally do not recommend to use this match.
    
    ```
    process:
      matchPaths:
      - path: [absolute executable path]
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute executable path]
        - dir: [absolute directory path]
          recursive: [true|false]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute exectuable path]
        - dir: [absolute directory path]
          recursive: [true|false]
      matchPatterns:
      - pattern: [regex pattern]
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute exectuable path]
        - dir: [absolute directory path]    
          recursive: [true|false]
    ```

    In each match, there are three options.
    
    - ownerOnly (false by default)
    
        ownerOnly works with the 'Allow' action only. If this is enabled, the executable(s) defined with matchPaths and matchDirectories will be executed by their owners only.
        
    - recursive (false by default)
    
        If this is enabled, the coverage will extend to the subdirectories of the directory defined with matchDirectories.
    
    - fromSource
    
        If a path or a directory is specified in fromSource, the executables defined with matchPaths or matchDirectories will be only launched by the executable of the path or the executables in the directory.

        For better understanding, let us say that an operator defines a policy as follows. Then, /bin/bash will be only allowed to execute /bin/sleep. Otherwise, the execution of /bin/sleep will be blocked.
        
        ```
        process:
          matchPaths:
          - path: /bin/sleep
            fromSource:
            - path: /bin/bash
        ```

- File

    The file section is quite similar to the process section.
    
    ```
    file:
      matchPaths:
      - path: [absolute file path]
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute file path]
        - dir: [absolute directory path]
          recursive: [true:false]
      matchDirectories:
      - dir: [absolute directory path]
        recursive: [true|false]            # --> optional
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute file path]
        - dir: [absolute directory path]
          recursive: [true:false]
      matchPatterns:
      - pattern: [regex pattern]
        readOnly: [true|false]             # --> optional
        ownerOnly: [true|false]            # --> optional
        fromSource:                        # --> optional (under development)
        - path: [absolute file path]
        - dir: [absolute directory path]
          recursive: [true:false]
    ```

    The only difference between 'process' and 'file' is the readOnly option.
    
    - readOnly (false by default)
    
        If this is enabled, the read operation will be only allowed, and any other operations (e.g., write) will be blocked.

- Capabilities

    In the case of capabilities, there are two types of matches: matchCapabilities and matchOperations. You can define specific capability names to allow or block using matchCapabilities. You can check available capabilities in [Capability List](./supported_capability_list.md). For convenience, KubeArmor also allows you to define certain operations at the high level rather than specifically defining capability names. You can check available operations in [Operation List](./supported_operation_list.md).
    
    ```
    capabilities:
      matchCapabilities:
      - [capability name]
      matchOperations:
      - [operation name]
    ```

- Action

    The action would be Allow, Block, or Audit. According to the action, given security policies will be handled in a blacklist manner or a whitelist manner. Thus, you need to define the action carefully. You can refer to [Consideration in Policy Action](./consideration_in_policy_action.md) for more details. In the case of Audit, it is similar to Block, but KubeArmor does not actually block specific executions or accesses. KubeArmor just generates some audit logs against the policy with the Audit action. Thus, we can use the Audit action for policy verification before applying a security policy with the Block action.
    
    ```
    action: [Allow|Block|Audit]
    ```
