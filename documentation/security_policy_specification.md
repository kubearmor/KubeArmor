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

  network:
    matchProtocols:
    - protocol: [TCP|UDP|ICMP]
      ipv4: [true|false]
      ipv6: [true|false]
    matchSources:
      process:
        matchPaths:
        - [absolute exectuable path]
        matchDirectories:
        - [absolute directory path]
      file:
        matchPaths:
        - [absolute file path]
        matchDirectories:
        - [absolute directory path]

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

    A security policy starts with base information such as apiVersion, kind, and metadata. The apiVersion and kind would be the same in any security policies. In the case of metadata, you only need to specify a policy's name and the name of a namespace where you will apply the policy.

    ```
    apiVersion: security.accuknox.com/v1
    kind:KubeArmorPolicy
    metadata:
      name: [policy name]
      namespace: [namespace name]
    ```

- Selector

    The selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify target pods or groups based on labels.
    
    ```
    selector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
     ```

- Process

    In the process section, there are three types of matches: matchPaths, matchDirectories, and matchPatterns. You can define specific executables using matchPaths or all executables in specific directories using matchDirectories. In the case of matchPatterns, advanced operators may be able to determine particular patterns for executables by using regular expressions. However, the coverage of regular expressions is highly dependent on AppArmor ([Policy Core Reference](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)). Thus, we do not recommend to use this match in general.
    
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

    In this section, there are three options.
    
    - ownerOnly (false by default)
    
        ownerOnly only works with the 'Allow' action. If this is enabled, the owner of an executable will only be allowed to execute it.
        
    - recursive (false by default)
    
        If this is enabled, the coverage will be extended to the given directory and its subdirectories.
    
    - fromSource
    
        If a path or a directory is specified, it means that the path or the directory in fromSource executes the executable in matchPaths or all executables in matchDirectories.

        Let us say that an operator defines a policy as follows. Then, /bin/bash will be only allowed to execute /bin/sleep. Otherwise, the execution of /bin/sleep will be blocked.
        
        ```
        process:
          matchPaths:
          - path: /bin/sleep
            fromSource:
            - path: /bin/sleep
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
    
        If this is enabled, the read operation will be only allowed. Otherwise, any other operations (e.g., write) will be blocked.

- Network

    In the network section, there are two types of matches: matchProtocols and matchSources. KubeArmor directly handles matchProtocols using LSMs, but KubeArmor lets other network security solutions handle matchSources through an eBPF map. You can see how matchSources works in [Integration with Network Security Solutions](./integration_with_network_security_solutions.md).
    
    In terms of matchProtocols, KubeArmor currently supports three types of protocols (i.e., TCP, UDP, and ICMP). In addition, you can add more information using ipv4 and ipv6 options. If ipv4 and ipv6 are not specified, both ipv4 and ipv6 are enabled by default.
 
    
    ```
    network:
      matchProtocols:
      - protocol: [TCP|UDP|ICMP]
        ipv4: [true|false]                 # --> optional
        ipv6: [true|false]                 # --> optional
      matchSources:
        process:
          matchPaths:
          - [absolute exectuable path]
          matchDirectories:
          - [absolute directory path]
        file:
          matchPaths:
          - [absolute file path]
          matchDirectories:
          - [absolute directory path]
    ```

- Capabilities

    In the case of capabilities, there are two types of matches: matchCapabilities and matchOperations. You can define specific capability names to allow or block using matchCapabilities. You can check available capabilities in [Capability List](./supported_capability_list.md). For convenience, KubeArmor also allows you to define certain operations at a high level rather than specifically defining capability names. You can check available operations in [Operation List](./supported_operation_list.md).
    
    ```
    capabilities:
      matchCapabilities:
      - [capability name]
      matchOperations:
      - [operation name]
    ```

- Action

    The action should be either Block or Allow. According to the action, given security policies will be handled in a blacklist manner or a whitelist manner. Thus, you need to define the action carefully. You can refer to [Consideration in Policy Action](./consideration_in_policy_action.md) for more details.
    
    ```
    action: [Allow|Block|Audit]
    ```
