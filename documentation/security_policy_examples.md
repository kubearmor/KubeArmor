# Security Policy Examples

Here, we demonstrate how to define security policies using our example microservice (multiubuntu).

- Process Restriction

    - Blcok a specific executable ([ksp-group-1-proc-path-block.yaml](../examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml))
    
        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-group-1-proc-path-block
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              group: group-1
          process:
            matchPaths:
            - path: /bin/sleep # try sleep 1
          action:
            Block
        ```
    
        The purpose of this policy is to block the execution of '/bin/sleep' in the containers that have the 'group-1' label. For this, we define the 'group-1' label in selector -> matchLabels and the specific path ('/bin/sleep') in process -> matchPaths. Also, we put 'Block' as the action of this policy.
        
    - Block all executables in a specific directory ([ksp-ubuntu-1-proc-dir-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-1-proc-dir-block.yaml))
    
        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-ubuntu-1-proc-dir-block
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              container: ubuntu-1
          process:
            matchDirectories:
            - dir: /sbin/ # try route
          action:
            Block
        ```
    
        The purpose of this policy is to block all executables in the '/sbin' directory. Since we want to block all executables rather than a specific executable, we use matchDirectories to specify the executables in the '/sbin' directory at once.
    
    - Block all executables in a specific directory and its subdirectories ([ksp-ubuntu-2-proc-dir-recursive-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-2-proc-dir-recursive-block.yaml))
    
        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-ubuntu-2-proc-dir-recursive-block
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              container: ubuntu-2
          process:
            matchDirectories:
            - dir: /usr/ # try env or whoami
              recursive: true
          action:
            Block
        ```
    
        As the extension of the previous policy, we want to block all executables in the '/usr' directory and its subdirectories (e.g., '/usr/bin', '/usr/sbin', and '/usr/local/bin'). Thus, we simply add 'recursive: ture' to extend the scope of the policy.
        
    - Allow specific executables only ([ksp-ubuntu-3-proc-dir-allow.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-3-proc-dir-allow.yaml))

        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-ubuntu-3-proc-dir-allow
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              container: ubuntu-3
          process:
            matchDirectories:
            - dir: /bin/
            - dir: /usr/bin/
          file: # some files to test
            matchDirectories:
              - dir: /credentials/
                recursive: true
          action:
            Allow
        ```
    
        Unlike the previous policies, we want for the containers that have the 'ubuntu-3' label to execute specific executables only. To achieve this goal, we first define the scope of this policy using matchDirectories (you can also use matchPaths). Then, we define the 'Allow' action instead of the 'Block' action. For policy verification, we allow some files (i.e., /credentials/*) as well.

- File Access Restriction

    - Allow accessing specific files only ([ksp-ubuntu-4-file-path-readonly-allow.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-4-file-path-readonly-allow.yaml))
    
        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-ubuntu-4-file-path-readonly-allow
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              container: ubuntu-4
          process: # some exectuables to test
            matchDirectories:
              - dir: /bin/
          file:
            matchPaths:
            - path: /secret.txt # echo "test" >> /secret.txt
            - path: /credentials/password # echo "test" >> /credentials/password
              readOnly: true
          action:
            Allow
        ```
    
        The purpose of this policy is to allow the containers that have the 'ubuntu-4' label to access '/secret.txt' and '/credentials/password' only. In addition, we want for them to read '/credentials/password' only (the write operation is blocked) while allowing them to read and write '/secret.txt'.
        
    - Block all file accesses in a specific directory and its subdirectories ([ksp-ubuntu-5-file-dir-recursive-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-5-file-dir-recursive-block.yaml))
    
        ```
        apiVersion: security.accuknox.com/v1
        kind: KubeArmorPolicy
        metadata:
          name: ksp-ubuntu-5-file-dir-recursive-block
          namespace: multiubuntu
        spec:
          selector:
            matchLabels:
              container: ubuntu-5
          file:
            matchDirectories:
            - dir: /credentials/
              recursive: true
          action:
            Block
        ```
    
        In this policy, we do not want to the containers that have the 'ubuntu-5' label to access any files in the '/credentials' directory and its subdirectories. Thus, we use 'matchDirectories' and 'recursive: ture' to define all files in the '/credentials' directory and its subdirectories.

- Network Operation Restriction

    - Block UDP and ICMP packets (non-TCP packets) ([ksp-ubuntu-5-net-udp-icmp-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-5-net-udp-icmp-block.yaml))

    ```
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-5-net-udp-icmp-block
      namespace: multiubuntu
    spec:
      selector:
        matchLabels:
          container: ubuntu-5
      network:
        matchProtocols:
        - protocol: udp
          ipv4: true
        - protocol: icmp
      action:
        Block
    ```

    In general, containers communicate with each other through TCP sessions; thus, we want to block the packets of other protocols. For this, we use matchProtocols to specify protocols (UDP and ICMP) to block. In addition, we define 'ipv4: true', meaning that we block UDP packets over IPv4, to show the flexibility of KubeArmor.

- Capabilities Restriction

    - Block Raw Sockets (i.e., non-TCP/UDP packets) ([ksp-ubuntu-2-cap-net-raw-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-2-cap-net-raw-block.yaml))

    ```
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-2-cap-net-raw-block
      namespace: multiubuntu
    spec:
      selector:
        matchLabels:
          container: ubuntu-2
      capabilities:
        matchCapabilities:
        - net_raw
      action:
        Block
    ```

    We want to block any network operations using raw sockets from the containers with the 'ubuntu-2' label, meaning that containers are not allowed to send non-TCP/UDP packets (e.g., ICMP echo request or reply) to other containers. To achieve this, we use matchCapabilities and specify the 'CAP_NET_RAW' capability to block raw socket creations inside the containers. Here, since we use stream and datagram sockets to TCP and UDP packets, respectively, we can still send those packets to others.
