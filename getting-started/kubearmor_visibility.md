# KubeArmor Visibility

KubeArmor currently supports enabling visibility for containers/hosts
Visibility for containers is enabled by default and can be accesed using `karmor` tool



## Getting Container Visibility
### Example : multiubuntu
* Prerequisites

 The following  example would require a K8s cluster , please follow [this](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md#prerequisites) to setup one if you dont have access to one


* Install karmor cli tool.

  ```text
  $ curl -sfL http://get.kubearmor.io/ | sudo sh -s -- -b /usr/local/bin
  ```
* Install KubeArmor

  ```text
  $ karmor install
  ```
* Deploying [multiubuntu](https://github.com/kubearmor/KubeArmor/blob/main/examples/multiubuntu.md) app and sample policies

  ```text
  $ kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/multiubuntu/multiubuntu-deployment.yaml
  $ kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml
  ```
* Checking default visibility

  * Container visibility is enabled by default in this case , we can check it using `kubectl describe` and greping `kubearmor-visibility `

  ```text
  $ POD_NAME=$(kubectl get pods -n multiubuntu -l "group=group-1,container=ubuntu-1" -o jsonpath='{.items[0].metadata.name}') && kubectl describe -n multiubuntu $POD_NAME |grep kubearmor-visibility 

  kubearmor-visibility: process,file,network,capabilities
  ```
  * Alternate : (For pre-existing workloads) Enable visibility using `kubectl annotate` , currently KubeArmor supports `process` , `file` , `network` , `capabilities`
   ```text
  $ kubectl annote pods <pod-name> -n multiubuntu "kubearmor-visibility=process,file,network,capabilities"
  ```
* Open up terminal , and watch logs using `karmor` cli
* 
  ```text
  $ karmor log
  ```
* In another terminal , simulate a policy violation , in this case trying `sleep` inside a pod

  ```text
  $ POD_NAME=$(kubectl get pods -n multiubuntu -l "group=group-1,container=ubuntu-1" -o jsonpath='{.items[0].metadata.name}') && kubectl -n multiubuntu exec -it $POD_NAME -- bash

  # sleep 1
  (Permission Denied)
  ```
* In the terminal running `karmor log` , the policy violation along with container visibility is shown , in this case for example
  <details>
  <summary>Click to expand</summary>
  
  ```text
    ClusterName: default
    HostName: sibashi-asus
    NamespaceName: multiubuntu
    PodName: ubuntu-1-deployment-5bd4dff469-4h79q
    Labels: group=group-1,container=ubuntu-1
    ContainerName: ubuntu-1-container
    ContainerID: 6e4b9f6c44fba27dc2d446dce69a32949ffcb6bb4304a34970141277fd81dff3
    ContainerImage: kubearmor/ubuntu-w-utils:0.1@sha256:b4693b003ed1fbf7f5ef2c8b9b3f96fd853c30e1b39549cf98bd772fbd99e260
    Type: MatchedPolicy
    PolicyName: ksp-group-1-proc-path-block
    Severity: 5
    Message: block /bin/sleep
    Source: /bin/bash
    Resource: /bin/sleep 1
    Operation: Process
    Action: Block
    Data: syscall=SYS_EXECVE
    Enforcer: AppArmor
    Result: Permission denied
    HostPID: 95090
    HostPPID: 94844
    PID: 112
    PPID: 101
    ParentProcessName: /bin/bash
  ```
  
  </details>


* The logs can also be generated in json format using `karmor log --json `

  <details>
  <summary>Click to expand</summary>
  
  ```json
  {   
    "Timestamp": 1672122722,
    "UpdatedTime": "2022-12-27T06:32:02.579168Z",
    "ClusterName": "default",
    "HostName": "sibashi-asus",
    "NamespaceName": "multiubuntu",
    "PodName": "ubuntu-1-deployment-777845b8f-hk76l",
    "Labels": "group=group-1,container=ubuntu-1",
    "ContainerID": "7dde0469f7996b82c380a4977610b7499c29c7aed0fac33e46142a5d87e4f047",
    "ContainerName": "ubuntu-1-container",
    "ContainerImage": "docker.io/kubearmor/ubuntu-w-utils:0.1@sha256:b4693b003ed1fbf7f5ef2c8b9b3f96fd853c30e1b39549cf98bd772fbd99e260",
    "HostPPID": 50243,
    "HostPID": 50352,
    "PPID": 113,
    "PID": 125,
    "ParentProcessName": "/bin/bash",
    "ProcessName": "/bin/sleep",
    "PolicyName": "ksp-group-1-proc-path-block",
    "Severity": "5",
    "Message": "block /bin/sleep",
    "Type": "MatchedPolicy",
    "Source": "/bin/bash",
    "Operation": "Process",
    "Resource": "/bin/sleep 1",
    "Data": "syscall=SYS_EXECVE",
    "Enforcer": "AppArmor",
    "Action": "Block",
    "Result": "Permission denied"
  }
  ```
  
  </details>
