# Examples of Host Security Policy

Here, we demonstrate how to define host security policies.

* Process Execution Restriction
  * Block a specific executable \([hsp-kubearmor-dev-proc-path-block.yaml](../examples/host-security-policies/hsp-kubearmor-dev-proc-path-block.yaml)\)

    ```text
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorHostPolicy
    metadata:
      name: hsp-kubearmor-dev-proc-path-block
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: kubearmor-dev
      severity: 5
      process:
        matchPaths:
        - path: /usr/bin/diff
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/usr/bin/diff' in a host whose host name is 'kubearmor-dev'. For this, we define 'kubernetes.io/hostname: kubearmor-dev' in nodeSelector -&gt; matchLabels and the specific path \('/usr/bin/diff'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please open a new terminal (or connect to the host with a new session) and run '/usr/bin/diff'. You will see that /usr/bin/diff is blocked.

    ---
    **NOTE**

    The given policy works with almost every linux distribution. If it is not working in your case, check the process location. The following location shows location of `sleep` binary in different ubuntu distributions:

    * In case of *Ubuntu 20.04* : /usr/bin/sleep
    * In case of *Ubuntu 18.04* : /bin/sleep
    ---

* File Access Restriction
  * Audit a critical file access \([hsp-kubearmor-dev-file-path-audit.yaml](../examples/multiubuntu/security-policies/hsp-kubearmor-dev-file-path-audit.yaml)\)

    ```text
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorHostPolicy
    metadata:
      name: hsp-kubearmor-dev-file-path-audit
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: kubearmor-dev
      severity: 5
      file:
        matchPaths:
        - path: /etc/passwd
      action:
        Audit
    ```

    * Explanation: The purpose of this policy is to audit any accesses to a critical file (i.e., '/etc/passwd'). Since we want to audit one critical file, we use matchPaths to specify the path of '/etc/passwd'.

    * Verification: After applying this policy, please open a new terminal (or connect to the host with a new session) and run 'sudo cat /etc/passwd'. Then, check the alert logs of KubeArmor.

* System calls alerting
  * Alert for all `unlink` syscalls
  ```text
  apiVersion: security.kubearmor.com/v1
  kind: KubeArmorHostPolicy
  metadata:
    name: audit-all-unlink
  spec:
    severity: 3
    nodeSelector:
          matchLabels:
            kubernetes.io/hostname: vagrant
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
  "Timestamp": 1661937152,
  "UpdatedTime": "2022-08-31T09:12:32.967304Z",
  "ClusterName": "default",
  "HostName": "vagrant",
  "HostPPID": 8563,
  "HostPID": 310459,
  "PPID": 8563,
  "PID": 310459,
  "UID": 1000,
  "ProcessName": "/usr/bin/unlink",
  "PolicyName": "audit-all-unlink",
  "Severity": "3",
  "Type": "MatchedHostPolicy",
  "Source": "/usr/bin/unlink /home/vagrant/secret.txt",
  "Operation": "Syscall",
  "Resource": "/home/vagrant/secret.txt",
  "Data": "syscall=SYS_UNLINK",
  "Action": "Audit",
  "Result": "Passed"
}
```
</details>

  * Alert on all `rmdir` syscalls targeting anything in `/home/` directory and sub-directories
  
  ```text
  apiVersion: security.kubearmor.com/v1
  kind: KubeArmorHostPolicy
  metadata:
    name: audit-home-rmdir
  spec:
    severity: 3
    nodeSelector:
          matchLabels:
            kubernetes.io/hostname: vagrant
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
  "Timestamp": 1661936983,
  "UpdatedTime": "2022-08-31T09:09:43.894787Z",
  "ClusterName": "default",
  "HostName": "vagrant",
  "HostPPID": 308001,
  "HostPID": 308002,
  "PPID": 308001,
  "PID": 308002,
  "ProcessName": "/usr/bin/rmdir",
  "PolicyName": "audit-home-rmdir",
  "Severity": "3",
  "Type": "MatchedHostPolicy",
  "Source": "/usr/bin/rmdir jane-doe",
  "Operation": "Syscall",
  "Resource": "/home/jane-doe",
  "Data": "syscall=SYS_RMDIR",
  "Action": "Audit",
  "Result": "Passed"
}
```
</details>
