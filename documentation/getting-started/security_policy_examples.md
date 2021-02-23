# Security Policy Examples

Here, we demonstrate how to define security policies using our example microservice \(multiubuntu\).

* Process Execution Restriction

  * Block a specific executable \([ksp-group-1-proc-path-block.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-group-1-proc-path-block
      namespace: multiubuntu
    spec:
      severity: 5
      selector:
        matchLabels:
          group: group-1
      process:
        matchPaths:
        - path: /bin/sleep
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/bin/sleep' in the containers with the 'group-1' label. For this, we define the 'group-1' label in selector -&gt; matchLabels and the specific path \('/bin/sleep'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please get into one of the containers with the 'group-1' \(using "kubectl -n multiubuntu exec -it ubuntu-X-deployment-... -- bash"\) and run '/bin/sleep'. You will see that /bin/sleep is blocked.

  * Block all executables in a specific directory \([ksp-ubuntu-1-proc-dir-block.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-1-proc-dir-block.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-1-proc-dir-block
      namespace: multiubuntu
    spec:
      severity: 1
      selector:
        matchLabels:
          container: ubuntu-1
      process:
        matchDirectories:
        - dir: /sbin/
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block all executables in the '/sbin' directory. Since we want to block all executables rather than a specific executable, we use matchDirectories to specify the executables in the '/sbin' directory at once.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-1' label and run '/sbin/route' to see if this command is allowed \(this command will be blocked\).

  * Block all executables in a specific directory and its subdirectories \([ksp-ubuntu-2-proc-dir-recursive-block.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-2-proc-dir-recursive-block.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-2-proc-dir-recursive-block
      namespace: multiubuntu
    spec:
      severity: 2
      selector:
        matchLabels:
          container: ubuntu-2
      process:
        matchDirectories:
        - dir: /usr/
          recursive: true
      action:
        Block
    ```

    * Explanation: As the extension of the previous policy, we want to block all executables in the '/usr' directory and its subdirectories \(e.g., '/usr/bin', '/usr/sbin', and '/usr/local/bin'\). Thus, we add 'recursive: true' to extend the scope of the policy.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-2' label and run '/usr/bin/env' or '/usr/bin/whoami'. You will see that those commands are blocked.

  * Allow specific executables only \([ksp-ubuntu-3-proc-dir-allow.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-3-proc-dir-allow.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-3-proc-dir-allow
      namespace: multiubuntu
    spec:
      severity: 5
      selector:
        matchLabels:
          container: ubuntu-3
      process:
        matchDirectories:
        - dir: /bin/
      file:
        matchDirectories:
          - dir: /credentials/ # some files to test
            recursive: true
      action:
        Allow
    ```

    * Explanation: Unlike the previous policies, we want the container with the 'ubuntu-3' label only to execute specific executables. To achieve this goal, we first define the scope of this policy using matchDirectories \(you can also use matchPaths\). Then, we define the 'Allow' action instead of the 'Block' action.

    * Verification: In this policy, we allow some files \(i.e., /credentials/\*\) for verification. After applying this policy, please get into the container with the 'ubuntu-3' label and run 'cd /credentials', 'ls', and 'cat /credentials/password'. You will see that all of the binaries in /bin work well. Now, please simply run 'awk' or 'diff'. Then, those commands will be blocked since they are in /usr/bin.

  * Allow a specific executable to be launched by its owner only \([ksp-ubuntu-3-proc-path-owner-only.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-3-proc-path-owner-only.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-3-proc-path-owner-allow
      namespace: multiubuntu
    spec:
      severity: 7
      selector:
        matchLabels:
          container: ubuntu-3
      process:
        matchPaths:
        - path: /home/user1/hello
          ownerOnly: true
        - path: /bin/su # need to change users
      file:
        matchDirectories: # some files are used by /bin/su (coarse-grained way)
        - dir: /etc/
          recursive: true
        - dir: /proc/
          recursive: true
        matchPaths:
        - path: /run/utmp # used by /bin/su
      action:
        Allow
    ```

    * Explanation: This policy aims to allow a specific user \(i.e., user1\) only to launch its own executable \(i.e., hello\), which means that we do not want for the root user to even launch /home/user1/hello. For this, we define a security policy similar to the above ones, but we specifically add 'ownerOnly: true'.

    * Verification: For verification, we allow /bin/su and some files used by /bin/su to change users \(from 'root' to 'user1'\) in the policy. After applying this policy, please get into the container with the 'ubuntu-3' label and run '/home/user1/hello' first. This command will be blocked even though you are the 'root' user. Then, please run 'su - user1'. Now, you are the 'user1' user. Please run '/home/user1/hello' again. You will see that it works now.

* File Access Restriction

  * Allow accessing specific files only \([ksp-ubuntu-4-file-path-readonly-allow.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-4-file-path-readonly-allow.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-4-file-path-readonly-allow
      namespace: multiubuntu
    spec:
      severity: 10
      selector:
        matchLabels:
          container: ubuntu-4
      process: # some exectuables to test
        matchDirectories:
          - dir: /bin/
      file:
        matchPaths:
        - path: /secret.txt
        - path: /credentials/password
          readOnly: true
      action:
        Allow
    ```

    * Explanation: The purpose of this policy is to allow the container with the 'ubuntu-4' label to access '/secret.txt' and '/credentials/password' only. We also want the container to read '/credentials/password' only \(the write operation is blocked\) while allowing the container to read and write '/secret.txt'.

    * Verification: For testing, we allow binaries in /bin. After applying this policy, please get into the container with the 'ubuntu-4' label and run 'cat /secret.txt' and 'cat /credentials/password'. You can see the contents in those files. Now, please run 'echo \"test\" &gt;&gt; /secret.txt'. This command will work fine. Please run 'echo \"test\" &gt;&gt; /credentials/password'. You will see that the write operation will be blocked.

  * Block all file accesses in a specific directory and its subdirectories \([ksp-ubuntu-5-file-dir-recursive-block.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-5-file-dir-recursive-block.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-5-file-dir-recursive-block
      namespace: multiubuntu
    spec:
      severity: 9
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

    * Explanation: In this policy, we do not want the container with the 'ubuntu-5' label to access any files in the '/credentials' directory and subdirectories. Thus, we use 'matchDirectories' and 'recursive: true' to define all files in the '/credentials' directory and its subdirectories.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-5' label and run 'cat /secret.txt'. You will see the contents of /secret.txt. Then, please run 'cat /credentials/password'. This command will be blocked due to the security policy.

* Network Operation Restriction

  * Block ICMP packets \([ksp-ubuntu-5-net-icmp-block](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-5-net-icmp-block.yaml)\)

    ```text
      apiVersion: security.accuknox.com/v1
      kind: KubeArmorPolicy
      metadata:
        name: ksp-ubuntu-5-net-icmp-block
        namespace: multiubuntu
      spec:
        severity: 8
        selector:
          matchLabels:
            container: ubuntu-5
        network:
          matchProtocols:
          - protocol: icmp
        action:
          Block
    ```

    * Explanation: We want to block sending ICMP packets from the containers with the 'ubuntu-5' label while allowing packets for the other protocols \(e.g., TCP and UDP\). For this, we use 'matchProtocols' to define the protocol \(i.e., ICMP\) that we want to block.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-5' label and run 'curl www.accuknox.com'. This will work fine. Then, please run 'ping 8.8.8.8'. You will see 'permission denied' since the 'ping' command internally uese the ICMP protocol.

* Capabilities Restriction

  * Block Raw Sockets \(i.e., non-TCP/UDP packets\) \([ksp-ubuntu-1-cap-net-raw-block.yaml](https://github.com/accuknox/KubeArmor/tree/master/examples/multiubuntu/security-policies/ksp-ubuntu-1-cap-net-raw-block.yaml)\)

    ```text
    apiVersion: security.accuknox.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-1-cap-net-raw-block
      namespace: multiubuntu
    spec:
      severity: 1
      selector:
        matchLabels:
          container: ubuntu-1
      capabilities:
        matchCapabilities:
        - capability: net_raw
      action:
        Block
    ```

    * Explanation: We want to block any network operations using raw sockets from the containers with the 'ubuntu-2' label, meaning that containers cannot send non-TCP/UDP packets \(e.g., ICMP echo request or reply\) to other containers. To achieve this, we use matchCapabilities and specify the 'CAP\_NET\_RAW' capability to block raw socket creations inside the containers. Here, since we use stream and datagram sockets to TCP and UDP packets respectively, we can still send those packets to others.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-1' label and run 'curl www.accuknox.com'. This will work fine. Then, please run 'ping 8.8.8.8'. You will see 'operation not permitted' since the 'ping' command internally requires a raw socket to send ICMP packets.
