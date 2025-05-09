# Examples of Security Policy

Here, we demonstrate how to define security policies using our example microservice \(multiubuntu\).

* Process Execution Restriction
  * Block a specific executable \([ksp-group-1-proc-path-block.yaml](../examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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
        - path: /bin/sleep
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/bin/sleep' in the containers with the 'group-1' label. For this, we define the 'group-1' label in selector -&gt; matchLabels and the specific path \('/bin/sleep'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please get into one of the containers with the 'group-1' \(using "kubectl -n multiubuntu exec -it ubuntu-X-deployment-... -- bash"\) and run '/bin/sleep'. You will see that /bin/sleep is blocked.

  * Block accessing specific executable matching labels, In & NotIn operator \([ksp-match-expression-in-notin-block-process.yaml](../examples/nginx-csp/cluster-security-policies/ksp-match-expression-in-notin-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-match-expression-in-notin-block-process
      namespace: multiubuntu
    spec:
      severity: 5
      message: "block execution of a matching binary name"
      selector:
        matchExpressions:
          - key: label
            operator: In
            values: 
              - container=ubuntu-1
          - key: label
            operator: NotIn
            values: 
              - container=ubuntu-3
      process:
        matchPaths:
        - execname: apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of 'apt' binary in all the workloads in the namespace `multiubuntu`, who contains label `container=ubuntu-1`. For this, we define the 'container=ubuntu-1' as value and operator as 'In' for key `label` in selector -&gt; matchExpressions and the specific execname \('apt'\) in process -&gt; matchPaths. The other expression `container=ubuntu-3` value and operator as 'NotIn' for key `label` is not mandatory because if we mention something in 'In' operator, everything else is just not slected for matching. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please exec into any container who contains label `container=ubuntu-1` within the namespace 'multiubuntu' and run 'apt'. You can see the binary is blocked. Then try to do same in other workloads who doesn't contains label `container=ubuntu-1`, the binary won't be blocked.

  * Block accessing specific executable matching labels, NotIn operator \([ksp-match-expression-notin-block-process.yaml](../examples/nginx-csp/cluster-security-policies/ksp-match-expression-notin-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-match-expression-notin-block-process
      namespace: multiubuntu
    spec:
      severity: 5
      message: "block execution of a matching binary name"
      selector:
        matchExpressions:
          - key: label
            operator: NotIn
            values: 
              - container=ubuntu-1
      process:
        matchPaths:
        - execname: apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of 'apt' binary in all the workloads in the namespace `multiubuntu`, who doesn't contains label `container=ubuntu-1`. For this, we define the 'container=ubuntu-1' as value and operator as 'In' for key `label` in selector -&gt; matchExpressions and the specific execname \('apt'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please exec into any container who contains label `container=ubuntu-1` within the namespace 'multiubuntu' and run 'apt'. You can see the binary is not blocked. Then try to do same in other workloads who doesn't contains label `container=ubuntu-1`, the binary will be blocked.

  * Block all executables in a specific directory \([ksp-ubuntu-1-proc-dir-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-1-proc-dir-block.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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
        - dir: /sbin/
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block all executables in the '/sbin' directory. Since we want to block all executables rather than a specific executable, we use matchDirectories to specify the executables in the '/sbin' directory at once.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-1' label and run '/sbin/route' to see if this command is allowed \(this command will be blocked\).

  * Block all executables in a specific directory and its subdirectories \([ksp-ubuntu-2-proc-dir-recursive-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-2-proc-dir-recursive-block.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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
        - dir: /usr/
          recursive: true
      action:
        Block
    ```

    * Explanation: As the extension of the previous policy, we want to block all executables in the '/usr' directory and its subdirectories \(e.g., '/usr/bin', '/usr/sbin', and '/usr/local/bin'\). Thus, we add 'recursive: true' to extend the scope of the policy.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-2' label and run '/usr/bin/env' or '/usr/bin/whoami'. You will see that those commands are blocked.

  * Allow specific executables to access certain files only \([ksp-ubuntu-3-file-dir-allow-from-source-path.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-3-file-dir-allow-from-source-path.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-3-file-dir-allow-from-source-path
      namespace: multiubuntu
    spec:
      severity: 10
      message: "a critical directory was accessed"
      tags:
      - WARNING
      selector:
        matchLabels:
          container: ubuntu-3
      file:
        matchDirectories:
        - dir: /credentials/
          fromSource:
          - path: /bin/cat
      action:
        Allow
    ```

    * Explanation: Here, we want the container with the 'ubuntu-3' label only to access certain files by specific executables. Otherwise, we want to block any other file accesses. To achieve this goal, we define the scope of this policy using matchDirectories with fromSource and use the 'Allow' action.

    * Verification: In this policy, we allow /bin/cat to access the files in /credentials only. After applying this policy, please get into the container with the 'ubuntu-3' label and run 'cat /credentials/password'. This command will be allowed with no errors. Now, please run 'cat /etc/hostname'. Then, this command will be blocked since /bin/cat is only allowed to access /credentials/\*.

  * Allow a specific executable to be launched by its owner only \([ksp-ubuntu-3-proc-path-owner-allow.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-3-proc-path-owner-allow.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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
        matchDirectories:
        - dir: /bin/ # required to change root to user1
          recursive: true
        - dir: /usr/bin/ # used in changing accounts
          recursive: true
      file:
        matchPaths:
        - path: /root/.bashrc # used by root
        - path: /root/.bash_history # used by root
        - path: /home/user1/.profile # used by user1
        - path: /home/user1/.bashrc # used by user1
        - path: /run/utmp # required to change root to user1
        - path: /dev/tty
        matchDirectories:
        - dir: /etc/ # required to change root to user1 (coarse-grained way)
          recursive: true
        - dir: /proc/ # required to change root to user1 (coarse-grained way)
          recursive: true
      action:
        Allow
    ```

    * Explanation: This policy aims to allow a specific user \(i.e., user1\) only to launch its own executable \(i.e., hello\), which means that we do not want for the root user to even launch /home/user1/hello. For this, we define a security policy with matchPaths and 'ownerOnly:  ture'.

    * Verification: For verification, we also allow several directories and files to change users \(from 'root' to 'user1'\) in the policy. After applying this policy, please get into the container with the 'ubuntu-3' label and run '/home/user1/hello' first. This command will be blocked even though you are the 'root' user. Then, please run 'su - user1'. Now, you are the 'user1' user. Please run '/home/user1/hello' again. You will see that it works now.

* File Access Restriction
  * Allow accessing specific files only \([ksp-ubuntu-4-file-path-readonly-allow.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-4-file-path-readonly-allow.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-4-file-path-readonly-allow
      namespace: multiubuntu
    spec:
      severity: 10
      message: "a critical file was accessed"
      tags:
      - WARNING
      selector:
        matchLabels:
          container: ubuntu-4
      process:
        matchDirectories:
        - dir: /bin/ # used by root
          recursive: true
        - dir: /usr/bin/ # used by root
          recursive: true
      file:
        matchPaths:
        - path: /credentials/password
          readOnly: true
        - path: /root/.bashrc # used by root
        - path: /root/.bash_history # used by root
        - path: /dev/tty
        matchDirectories:
        - dir: /etc/ # used by root (coarse-grained way)
          recursive: true
        - dir: /proc/ # used by root (coarse-grained way)
          recursive: true
      action:
        Allow
    ```

    * Explanation: The purpose of this policy is to allow the container with the 'ubuntu-4' label to read '/credentials/password' only \(the write operation is blocked\).

    * Verification: After applying this policy, please get into the container with the 'ubuntu-4' label and run 'cat /credentials/password'. You can see the contents in the file. Now, please run 'echo \"test\" &gt;&gt; /credentials/password'. You will see that the write operation will be blocked.

  * Block all file accesses in a specific directory and its subdirectories \([ksp-ubuntu-5-file-dir-recursive-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-5-file-dir-recursive-block.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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

    * Explanation: In this policy, we do not want the container with the 'ubuntu-5' label to access any files in the '/credentials' directory and its subdirectories. Thus, we use 'matchDirectories' and 'recursive: true' to define all files in the '/credentials' directory and its subdirectories.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-5' label and run 'cat /secret.txt'. You will see the contents of /secret.txt. Then, please run 'cat /credentials/password'. This command will be blocked due to the security policy.

* Network Operation Restriction
  * Audit ICMP packets \([ksp-ubuntu-5-net-icmp-audit](../examples/multiubuntu/security-policies/ksp-ubuntu-5-net-icmp-audit.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: ksp-ubuntu-5-net-icmp-audit
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
        Audit
    ```

    * Explanation: We want to audit sending ICMP packets from the containers with the 'ubuntu-5' label while allowing packets for the other protocols \(e.g., TCP and UDP\). For this, we use 'matchProtocols' to define the protocol \(i.e., ICMP\) that we want to block.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-5' label and run 'curl https://kubernetes.io/'. This will work fine. Then, run 'ping 8.8.8.8'. You will see 'Permission denied' since the 'ping' command internally uses the ICMP protocol.

* Capabilities Restriction
  * Block Raw Sockets \(i.e., non-TCP/UDP packets\) \([ksp-ubuntu-1-cap-net-raw-block.yaml](../examples/multiubuntu/security-policies/ksp-ubuntu-1-cap-net-raw-block.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
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

    * Explanation: We want to block any network operations using raw sockets from the containers with the 'ubuntu-1' label, meaning that containers cannot send non-TCP/UDP packets \(e.g., ICMP echo request or reply\) to other containers. To achieve this, we use matchCapabilities and specify the 'CAP\_NET\_RAW' capability to block raw socket creations inside the containers. Here, since we use the stream and datagram sockets to TCP and UDP packets respectively, we can still send those packets to others.

    * Verification: After applying this policy, please get into the container with the 'ubuntu-1' label and run 'curl https://kubernetes.io/'. This will work fine. Then, run 'ping 8.8.8.8'. You will see 'Operation not permitted' since the 'ping' command internally requires a raw socket to send ICMP packets.

* System calls alerting
  * Alert for all `unlink` syscalls

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: audit-all-unlink
      namespace: default
    spec:
      severity: 3
      selector:
        matchLabels:
          container: ubuntu-1
      syscalls:
        matchSyscalls:
        - syscall:
          - unlink
      action:
        Audit
    ```

<details>
<summary>Generated telemetry</summary>

```json
{
  "Timestamp": 1661936135,
  "UpdatedTime": "2022-08-31T08:55:35.368285Z",
  "ClusterName": "default",
  "HostName": "vagrant",
  "NamespaceName": "default",
  "PodName": "ubuntu-1-6779f689b5-jjcvh",
  "Labels": "container=ubuntu-1",
  "ContainerID": "1f613df8390b9d2e4e89d0323ac0b9a2e7d7ddcc460720e15074f8c497aec0df",
  "ContainerName": "nginx",
  "ContainerImage": "nginx:latest@sha256:b95a99feebf7797479e0c5eb5ec0bdfa5d9f504bc94da550c2f58e839ea6914f",
  "HostPPID": 255296,
  "HostPID": 296264,
  "PPID": 47,
  "PID": 65,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/usr/bin/unlink",
  "PolicyName": "audit-all-unlink",
  "Severity": "3",
  "Type": "MatchedPolicy",
  "Source": "/usr/bin/unlink home/secret.txt",
  "Operation": "Syscall",
  "Resource": "/home/secret.txt",
  "Data": "syscall=SYS_UNLINK",
  "Action": "Audit",
  "Result": "Passed"
}
```

</details>

  * Alert on all `rmdir` syscalls targeting anything in `/home/` directory and sub-directories

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorPolicy
    metadata:
      name: audit-home-rmdir
      namespace: default
    spec:
      selector:
        matchLabels:
          container: ubuntu-1
      syscalls:
        matchPaths:
        - syscall:
          - rmdir
          path: /home/
          recursive: true
      action:
        Audit
    ```

<details>
<summary>Generated telemetry</summary>

```json
{
  "Timestamp": 1661936575,
  "UpdatedTime": "2022-08-31T09:02:55.841537Z",
  "ClusterName": "default",
  "HostName": "vagrant",
  "NamespaceName": "default",
  "PodName": "ubuntu-1-6779f689b5-jjcvh",
  "Labels": "container=ubuntu-1",
  "ContainerID": "1f613df8390b9d2e4e89d0323ac0b9a2e7d7ddcc460720e15074f8c497aec0df",
  "ContainerName": "nginx",
  "ContainerImage": "nginx:latest@sha256:b95a99feebf7797479e0c5eb5ec0bdfa5d9f504bc94da550c2f58e839ea6914f",
  "HostPPID": 255296,
  "HostPID": 302715,
  "PPID": 47,
  "PID": 67,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/bin/rmdir",
  "PolicyName": "audit-home-rmdir",
  "Severity": "1",
  "Type": "MatchedPolicy",
  "Source": "/bin/rmdir home/jane-doe/",
  "Operation": "Syscall",
  "Resource": "/home/jane-doe",
  "Data": "syscall=SYS_RMDIR",
  "Action": "Audit",
  "Result": "Passed"
}
```

</details>
