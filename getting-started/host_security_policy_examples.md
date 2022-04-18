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
