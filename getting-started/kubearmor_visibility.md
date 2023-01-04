# KubeArmor Visibility

KubeArmor currently supports enabling visibility for containers/hosts.

Visibility for containers is enabled by default and can be accessed using the `karmor` tool.


<details>
  <summary>Know More On Visibillity</summary>

#### KubeArmor provides visibility on the following behavior of containers
* Process
* Files
* Networks

</details>


## Getting Container Visibility

##### Prerequisites

* If you don't have access to a K8s cluster, please follow  [this](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#prerequisites) to set one up.
* To install karmor CLI tool in the cluster follow [here](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#1-download-and-install-karmor-cli-tool)

#### Example: wordpress-mysql

* To deploy [wordpress-mysql](https://github.com/kubearmor/KubeArmor/blob/main/examples/multiubuntu.md) app follow [this](https://github.com/kubearmor/KubeArmor/blob/main//examples/wordpress-mysql.md)
* Now we need to deploy some sample policies
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/wordpress-mysql/security-policies/ksp-wordpress-block-process.yaml
```
This sample policy blocks execution of the `apt` and `apt-get` commands in wordpress pods with label selector `app: wordpress`.

* Checking default visibility

  * Container visibility is enabled by default, in this case, we can check it using `kubectl describe` and greping `kubearmor-visibility `

  ```text
  $ POD_NAME=$(kubectl get pods -n wordpress-mysql -l app=wordpress -o jsonpath='{.items[0].metadata.name}') && kubectl describe -n wordpress-mysql pod $POD_NAME | grep kubearmor-visibility

  kubearmor-visibility: process, file, network, capabilities
  ```
  * Alternate : (For pre-existing workloads) Enable visibility using `kubectl annotate`, currently KubeArmor supports `process`, `file`, `network`, `capabilities`
   ```text
  $ kubectl annotate pods <pod-name> -n wordpress-mysql "kubearmor-visibility=process,file,network,capabilities"
  ```
* Open up a terminal, and watch logs using the `karmor` cli
  ```text
  $ karmor log
  ```
* In another terminal, simulate a policy violation, in this case trying `sleep` inside a pod

  ```text
  POD_NAME=$(kubectl get pods -n wordpress-mysql -l app=wordpress -o jsonpath='{.items[0].metadata.name}') && kubectl -n wordpress-mysql exec -it $POD_NAME -- bash
  # apt update
  ```
* In the terminal running `karmor log`, the policy violation along with container visibility is shown, in this case for example
  <details>
  <summary>Click to expand</summary>

  ```text
  == Alert / 2023-01-04 04:58:37.689182 ==
  ClusterName: default
  HostName: sibashi-asus
  NamespaceName: wordpress-mysql
  PodName: wordpress-787f45786f-mm2bm
  Labels: app=wordpress
  ContainerName: wordpress
  ContainerID: 9af5246810fd0a732e74d391b32b95f65e4c08e655d1ab10b49b04b148cc1c24
  ContainerImage: docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845
  Type: MatchedPolicy
  PolicyName: ksp-wordpress-block-process
  Severity: 3
  Source: /bin/bash
  Resource: /usr/bin/apt update
  Operation: Process
  Action: Block
  Data: syscall=SYS_EXECVE
  Enforcer: AppArmor
  Result: Permission denied
  HostPID: 17462
  HostPPID: 17293
  PID: 199
  PPID: 193
  ParentProcessName: /bin/bash
  ProcessName: /usr/bin/apt
  ```

  </details>


* The logs can also be generated in JSON format using `karmor log --json `

  <details>
  <summary>Click to expand</summary>

  ```json
  {
  "Timestamp":1672808328,
  "UpdatedTime":"2023-01-04T04:58:48.838991Z",
  "ClusterName":"default","HostName":"sibashi-asus",
  "NamespaceName":"wordpress-mysql","PodName":"wordpress-787f45786f-mm2bm",
  "Labels":"app=wordpress",
  "ContainerID":"9af5246810fd0a732e74d391b32b95f65e4c08e655d1ab10b49b04b148cc1c24",
  "ContainerName":"wordpress",
  "ContainerImage":"docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "HostPPID":17293,
  "HostPID":17526,
  "PPID":193,
  "PID":200,
  "ParentProcessName":"/bin/bash",
  "ProcessName":"/usr/bin/apt",
  "PolicyName":"ksp-wordpress-block-process",
  "Severity":"3",
  "Type":"MatchedPolicy",
  "Source":"/bin/bash",
  "Operation":"Process",
  "Resource":"/usr/bin/apt update",
  "Data":"syscall=SYS_EXECVE",
  "Enforcer":"AppArmor",
  "Action":"Block",
  "Result":"Permission denied"
  }

  ```

  </details>
