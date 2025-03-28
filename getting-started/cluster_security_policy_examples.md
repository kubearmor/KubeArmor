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

  * Block a specific executable matching labels, In operator- In operator \([csp-matchlabels-in-block-process.yaml](../examples/nginx-csp/cluster-security-policies/csp-matchlabels-in-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-matchlabels-in-block-process
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: In
            values:
              - nginx1
          - key: label
            operator: In
            values:
              - app=nginx
              - app=nginx-dev
      process:
        matchPaths:
          - path: /usr/bin/apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/usr/bin/apt' in the workloads who match the labels `app=nginx` OR `app=nginx-dev` present in the namespace `nginx1` . For this, we define the 'nginx1' as value and operator as 'In' for key `namespace` AND `app=nginx` & `app=nginx-dev` value and operator as 'In' for key `label` in selector -&gt; matchExpressions and the specific path \('/usr/bin/apt'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please get into one of the containers in the namespace 'nginx1' \(using "kubectl -n nginx1 exec -it nginx-X-... -- bash"\) and run '/usr/bin/apt'. You will see that /usr/bin/apt is blocked. `apt` won't be blocked in a workload that doesn't have labels `app=nginx` OR `app=nginx-dev` in namespace `nginx1` and all the workloads across other namespaces.

  * Block accessing specific executable matching labels, NotIn operator \([csp-matchlabels-not-in-block-process.yaml](../examples/nginx-csp/cluster-security-policies/csp-matchlabels-not-in-block-process.yaml)\)

    ```yaml
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorClusterPolicy
    metadata:
      name: csp-matchlabels-not-in-block-process
    spec:
      severity: 8
      selector:
        matchExpressions:
          - key: namespace
            operator: NotIn
            values:
              - nginx2
          - key: label
            operator: NotIn
            values:
              - app=nginx
      process:
        matchPaths:
          - path: /usr/bin/apt
      action:
        Block
    ```

    * Explanation: The purpose of this policy is to block the execution of '/usr/bin/apt' in all the workloads who doesn't match the labels `app=nginx` AND not present in the namespace `nginx2` . For this, we define the 'nginx2' as value and operator as 'NotIn' for key `namespace` AND `app=nginx` value and operator as 'NotIn' for key `label` in selector -&gt; matchExpressions and the specific path \('/usr/bin/apt'\) in process -&gt; matchPaths. Also, we put 'Block' as the action of this policy.


    * Verification: After applying this policy, please exec into any container within the namespace 'nginx2' and run '/usr/bin/apt'. You can see the  operation is blocked. Then try to do same in other workloads present in different namespace and if they don't have label `app=nginx`, the operation will be blocked, in case container have label `app=nginx`, operation won't be blocked.

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
