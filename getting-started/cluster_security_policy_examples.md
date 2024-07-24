# Examples of Cluster Security Policy

Here, we demonstrate how to define a cluster security policies.

* Process Execution Restriction
  * Block a specific executable - In operator \([csp-in-operator-block-process.yaml](../examples/nginx-csp/cluster-security-policies/csp-in-operator-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-in-operator-block-process
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: In
            values:
              - nginx1
      process:
        matchPaths:
          - path: /usr/bin/apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/usr/bin/apt' in the containers present in the namespace nginx1. For this, we define the 'nginx1' value and operator as 'In' in selector -&gt; matchExpressions and the specific path \('/usr/bin/apt'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please get into one of the containers in the namespace 'nginx1' \(using "kubectl -n nginx1 exec -it nginx-X-... -- bash"\) and run '/usr/bin/apt'. You will see that /usr/bin/apt is blocked.

  * Block a specific executable - NotIn operator\([csp-not-in-operator-block-process.yaml](../examples/nginx-csp/cluster-security-policies/csp-not-in-operator-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-in-operator-block-process
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: NotIn
            values:
              - nginx1
      process:
        matchPaths:
          - path: /usr/bin/apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/usr/bin/apt' in all containers present in the cluster except that are in the namespace nginx1. For this, we define the 'nginx1' value and operator as 'NotIn' in selector -&gt; matchExpressions and the specific path \('/usr/bin/apt'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please get into one of the containers in the namespace 'nginx1' \(using "kubectl -n nginx1 exec -it nginx-X-... -- bash"\) and run '/usr/bin/apt'. You will see that /usr/bin/apt is not blocked. Now try running same command in container inside 'nginx2' namespace and it should not be blocked.

* File Access Restriction
  * Block accessing specific file \([csp-in-operator-block-file-access.yaml](../examples/nginx-csp/cluster-security-policies/csp-in-operator-block-file-access.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-in-operator-block-file-access
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: In
            values:
              - nginx2
      file:
        matchPaths:
          - path: /etc/host.conf
            fromSource:
            - path: /usr/bin/cat
      action:
        Block

    ```

    * Explanation: The purpose of this policy is to block the container within the namespace 'nginx2' to read '/etc/host.conf'.

    * Verification: After applying this policy, please get into the container within the namespace 'nginx2' and run 'cat /etc/host.conf'. You can see the  operation is blocked.

  * Block accessing specific file \([csp-in-operator-block-file-access.yaml](../examples/nginx-csp/cluster-security-policies/csp-in-operator-block-file-access.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-in-operator-block-file-access
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: NotIn
            values:
              - nginx2
      file:
        matchPaths:
          - path: /etc/host.conf
            fromSource:
            - path: /usr/bin/cat
      action:
        Block

    ```

    * Explanation: The purpose of this policy is to block read access for '/etc/host.conf' in all the containers except the namespace 'bginx2'.

    * Verification: After applying this policy, please get into the container within the namespace 'nginx2' and run 'cat /etc/host.conf'. You can see the  operation is not blocked and can see the content of the file. Now try to run 'cat /etc/host.conf' in container of 'nginx1' namespace, this operation should be blocked.

> **Note** Other operations like Network, Capabilities, Syscalls also behave in same way as in security policy. The difference only lies in how we match the cluster policy with the namespaces.
