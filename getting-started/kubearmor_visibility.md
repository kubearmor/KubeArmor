# KubeArmor Visibility

There are only two sources of visibility configuration: the `kubearmor-visibility` annotation on the namespace and the visibility set in the `kubearmor-config` ConfigMap.

The `karmor` tool provides access to both using `karmor logs`.

<details>
  <summary>Available visibility options:</summary>

#### KubeArmor provides visibility on the following behavior of containers
* Process
* Files
* Networks

</details>


### Prerequisites

* If you don't have access to a K8s cluster, please follow  [this](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#prerequisites) to set one up.
* karmor CLI tool: [Download and install karmor-cli](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#1-download-and-install-karmor-cli-tool)

### Example: wordpress-mysql

* To deploy [wordpress-mysql](https://github.com/kubearmor/KubeArmor/blob/main/examples/wordpress-mysql/wordpress-mysql-deployment.yaml) app follow [this](https://github.com/kubearmor/KubeArmor/blob/main//examples/wordpress-mysql.md)
* Now we need to deploy some sample policies
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/wordpress-mysql/security-policies/ksp-wordpress-block-process.yaml
```
This sample policy blocks execution of the `apt` and `apt-get` commands in wordpress pods with label selector `app: wordpress`.

### ConfigMap Visibility

 KubeArmor has the ability to let the user select what kind of events have to be traced by changing the `visibility` at the `KubeArmorConfig` configmap.
 However it is not recommended to manually tamper with the configmap and the right way to do it is via editing the `KubeArmorConfig` resource named `kubearmor-default` in `kubearmor` namespace and setting `defaultVisibility`.

* Checking ConfigMap visibility configuration

  * Visibility configuration in ConfigMap can be checked using `kubectl describe`. 

  ```text
  kubectl get configmap kubearmor-config -n kubearmor -o yaml | grep visibility

  visibility: process,network
  ```
  * Visibility configuration in `kubearmor-default` resource can be checked using `kubectl describe`. 

  ```text
  kubectl describe kubearmorconfig kubearmor-default -n kubearmor | grep "defaultVisibillity"

  defaultVisibility: process,network
  ```
  * **To update the visibility configuration of configMap :**  It's recommended to edit the KubeArmorConfig resource named `kubearmor-default` in the kubearmor namespace and set the `defaultVisibility` field.
 
   ```text
    kubectl edit kubearmorconfig kubearmor-default -n kubearmor

  ```

* Now we can get general telemetry events using karmor logs. Open up a terminal, and watch logs using the karmor cli
  ```text
   karmor logs --logFilter=system

  ```
  
* In another terminal, let's exec into the pod and run some process commands . Try `ls` inside the pod

  ```text
    POD_NAME=$(kubectl get pods -n wordpress-mysql -l app=wordpress -o jsonpath='{.items[0].metadata.name}') && kubectl -n wordpress-mysql exec -it $POD_NAME -- bash
  # ls
  ```
   Now, we can notice logs have been generated for the above command and logs with only `Operation: Network` and `Operation: Process` are shown as configured in default visibility.

   <details>
  <summary>Click to expand</summary>

  ```text
  
  == Log / 2023-01-27 14:41:49.017709 ==
  ClusterName: default
  HostName: kubearmor-dev2
  Type: HostLog
  Source: /usr/bin/dockerd
  Resource: /usr/bin/runc --version
  Operation: Process
  Data: syscall=SYS_EXECVE
  Result: Passed
  HostPID: 193088
  HostPPID: 914
  PID: 193088
  PPID: 914
  ParentProcessName: /usr/bin/dockerd
  ProcessName: /usr/bin/runc
  == Log / 2023-01-27 14:41:49.018951 ==
  ClusterName: default
  HostName: kubearmor-dev2
  Type: HostLog
  Source: /usr/bin/runc --version
  Resource: /lib/x86_64-linux-gnu/libc.so.6
  Operation: File
  Data: syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_CLOEXEC
  Result: Passed
  HostPID: 193088
  HostPPID: 914
  PID: 193088
  PPID: 914
  ParentProcessName: /usr/bin/dockerd
  ProcessName: /usr/bin/runc
  == Log / 2023-01-27 14:41:49.018883 ==
  ClusterName: default
  HostName: kubearmor-dev2
  Type: HostLog
  Source: /usr/bin/runc --version
  Resource: /etc/ld.so.cache
  Operation: File
  Data: syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_CLOEXEC
  Result: Passed
  HostPID: 193088
  HostPPID: 914
  PID: 193088
  PPID: 914
  ParentProcessName: /usr/bin/dockerd
  ProcessName: /usr/bin/runc
  == Log / 2023-01-27 14:41:49.020905 ==
  ClusterName: default
  HostName: kubearmor-dev2
  Type: HostLog
  Source: /var/lib/rancher/k3s/data/2949af7261ce923f6a5091396d266a0e9d9436dcee976fcd548edc324eb277bb/bin/k3s
  Resource: /var/lib/rancher/k3s/data/2949af7261ce923f6a5091396d266a0e9d9436dcee976fcd548edc324eb277bb/bin/portmap
  Operation: Process
  Data: syscall=SYS_EXECVE
  Result: Passed
  HostPID: 193090
  HostPPID: 5627
  PID: 193090
  PPID: 5627
  ParentProcessName: /var/lib/rancher/k3s/data/2949af7261ce923f6a5091396d266a0e9d9436dcee976fcd548edc324eb277bb/bin/k3s
  ProcessName: /var/lib/rancher/k3s/data/2949af7261ce923f6a5091396d266a0e9d9436dcee976fcd548edc324eb277bb/bin/portmap

    ```

    <details>

> Note: While default visibility settings set through the ConfigMap provide a broad stroke for monitoring events within a Kubernetes cluster, there are cases where specific applications or use cases necessitate finer control over visibility settings like as in a case like [this](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#audit-access-to-folderspaths). Namespace visibility settings can override the default visibility configurations set at the ConfigMap level, allowing for tailored monitoring and enforcement within specific namespaces.

### Updating Namespace Visibility

KubeArmor has the ability to let the user select what kind of events have to be traced by changing the annotation `kubearmor-visibility` at the namespace.

* Checking Namespace visibility

  * Namespace visibility can be checked using `kubectl describe`. 

  ```text
  kubectl describe ns wordpress-mysql | grep kubearmor-visibility

  kubearmor-visibility: process, file, network, capabilities
  ```
  > Note: By default namespace annotations are set to none.

  * **To update the visibility of namespace :** Now let's update Kubearmor visibility using `kubectl annotate`. Currently KubeArmor supports `process`, `file`, `network`, `capabilities`.
  Lets try to update visibility for the namespace `wordpress-mysql`
 
   ```text
    kubectl annotate ns wordpress-mysql kubearmor-visibility=network --overwrite
    "namespace/wordpress-mysql annotated"

  ```
    > Note: To turn off the visibility across all aspects, use `kubearmor-visibility=none`. Note that any policy violations or events that results in non-success returns would still be reported in the logs.

* Open up a terminal, and watch logs using the `karmor` cli
  ```text
  karmor logs --logFilter=all -n wordpress-mysql

  ```
  
* In another terminal, let's exec into the pod and run some process commands . Try `ls` inside the pod

  ```text
    POD_NAME=$(kubectl get pods -n wordpress-mysql -l app=wordpress -o jsonpath='{.items[0].metadata.name}') && kubectl -n wordpress-mysql exec -it $POD_NAME -- bash
  # ls
  ```
  Now, we can notice that no logs have been generated for the above command and logs with only `Operation: Network` are shown.
  >**Note** If telemetry is disabled, the user wont get audit event even if there is an audit rule.

  >**Note** Only the logs are affected by changing the visibility, we still get all the alerts that are generated.

* Let's simulate a sample policy violation, and see whether we still get alerts or not.
    * **Policy violation :**
    ```text
    POD_NAME=$(kubectl get pods -n wordpress-mysql -l app=wordpress -o jsonpath='{.items[0].metadata.name}') && kubectl -n wordpress-mysql exec -it $POD_NAME -- bash
    #apt 
    ```
    Here, note that the alert with `Operation: Process` is reported.
  <details>
  <summary>Click to expand</summary>

  ```text
  == Alert / 2023-04-21 10:54:16.167986 ==
  ClusterName: default
  HostName: aryan-vm
  NamespaceName: wordpress-mysql
  PodName: wordpress-c4bf5b44b-wsfkg
  Labels: app=wordpress
  ContainerName: wordpress
  ContainerID: f6fa783eac62b3cc315059c349e88aa851bd87e3e8d4e91ac539dc2a6ca71ae6
  ContainerImage: wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845
  Type: MatchedPolicy
  PolicyName: ksp-wordpress-block-process
  Severity: 3
  Source: /bin/bash
  Resource: /usr/bin/apt
  Operation: Process
  Action: Block
  Data: syscall=SYS_EXECVE
  Enforcer: AppArmor
  Result: Permission denied
  HostPID: 1.252628e+06
  HostPPID: 1.251261e+06
  PID: 200
  PPID: 192
  ParentProcessName: /bin/bash
  ProcessName: /usr/bin/apt

  ```
  </details>
