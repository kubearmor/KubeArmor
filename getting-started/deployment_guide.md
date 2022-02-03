# Getting Started Guide

If you do not already have a k8s cluster, check the [pre-requisites](#prerequisites) to setup one.

If you want to try KubeArmor directly on the host without k8s, [use kubearmor in systemd mode](kubearmor_vm.md).

## Deployment Steps

### 1. Download and install karmor cli-tool
```
curl -sfL https://raw.githubusercontent.com/kubearmor/kubearmor-client/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

### 2. Install KubeArmor
```
karmor install
```

<details>
  <summary>Output of karmor install</summary>

```
aws@pandora:~$ karmor install
Auto Detected Environment : docker
CRD kubearmorpolicies.security.kubearmor.com ...
CRD kubearmorhostpolicies.security.kubearmor.com ...
Service Account ...
Cluster Role Bindings ...
KubeArmor Relay Service ...
KubeArmor Relay Deployment ...
KubeArmor DaemonSet ...
KubeArmor Policy Manager Service ...
KubeArmor Policy Manager Deployment ...
KubeArmor Host Policy Manager Service ...
KubeArmor Host Policy Manager Deployment ...
```
</details>

It is assumed that the k8s cluster is already present/reachable setup with the [*required prerequisites*](#Prerequisites) and the user has rights to create service-accounts and cluster-role-bindings.

### 3. Deploying sample app and policies
   
#### a. Deploy sample [multiubuntu app](../examples/multiubuntu.md)
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/multiubuntu/multiubuntu-deployment.yaml
```

#### b. Deploy [sample policies](security_policy_examples.md)
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml
```
This sample policy blocks execution of `sleep` command in ubuntu-1 pods.

#### c. Simulate policy violation
```
$ POD_NAME=$(kubectl get pods -n multiubuntu -l "group=group-1,container=ubuntu-1" -o jsonpath='{.items[0].metadata.name}') && kubectl -n multiubuntu exec -it $POD_NAME -- bash
# sleep 1
(Permission Denied)
```
### 4. Getting Alerts/Telemetry from KubeArmor

#### a. Enable port-forwarding for KubeArmor relay (if needed)
```
kubectl port-forward -n kube-system svc/kubearmor 32767:32767
```

#### b. Observing logs using karmor cli
```
karmor log
```

## K8s platforms tested
1. Google Kubernetes Engine (GKE) with Container Optimized OS (COS)
2. GKE with Ubuntu image
3. [Amazon Elastic Kubernetes Service (EKS)](../deployments/EKS)
4. Self-managed (on-prem) k8s
5. Local k8s engines (k3s, microk8s, and minikube)

## Cluster Setup

#### EKS Cluster Setup

<details>
  <summary>Click to expand!</summary>

### Deploy KubeArmor on EKS

#### 1. Prerequisite for the deployment

- Set up AWS credentials on your system

  Follow [Getting started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html "Getting started with Amazon EKS")

- Install eksctl

  Install eksctl on your local system

  ```
  curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
  sudo mv /tmp/eksctl /usr/local/bin
  eksctl version
  ```

#### 2. Creating an EKS cluster

- Create ClusterConfig (eks-config.yaml)

  <details>
    <summary>(Option 1) Create an EKS cluster configuration using Ubuntu 20.04 </summary>

    KubeArmor needs kernel headers installed on each node, so we create an EKS cluster with the following configuration:

    ```yaml
    apiVersion: eksctl.io/v1alpha5
    kind: ClusterConfig

    metadata:
      name: kubearmor-ub20
      region: us-east-2

    nodeGroups:
      - name: ng-1
        amiFamily: "Ubuntu2004"
        desiredCapacity: 1
        ssh:
          allow: true
        preBootstrapCommands:
          - "sudo apt install linux-headers-$(uname -r)"
    ```

    Save the above EKS `ClusterConfig` yaml as `eks-config.yaml`.
  </details>

  <details>
    <summary>(Option 2) Create an EKS cluster configuration using Amazon Linux 2 </summary>

    KubeArmor needs kernel headers installed on each node, so we create an EKS cluster with the following configuration:

    ```yaml
    apiVersion: eksctl.io/v1alpha5
    kind: ClusterConfig

    metadata:
      name: kubearmor-cluster
      region: us-east-2

    nodeGroups:
      - name: ng-1
        desiredCapacity: 2
        ssh:
          allow: true

        preBootstrapCommands:
          - "sudo yum install -y kernel-devel-$(uname --kernel-release)"
    ```

    Save the above EKS `ClusterConfig` yaml as `eks-config.yaml`.

  ##### Limitation

  KubeArmor on RedHat based Linux distributions currently supports the audit mode only, which means that you are not able to enforce security policies while the events related to the policies can be audited.
  </details>

- Create the EKS cluster:

  Create the cluster using eksctl
  ```
  eksctl create cluster -f ./eks-config.yaml
  ```

  <details>
    <summary>Output for eksctl create cluster</summary>

    ```
    aws@pandora:~$ eksctl create cluster -f ./eks-ub20.yaml
    2021-11-09 07:30:48 [ℹ]  eksctl version 0.70.0
    2021-11-09 07:30:48 [ℹ]  using region us-east-2
    2021-11-09 07:30:49 [ℹ]  setting availability zones to [us-east-2b us-east-2a us-east-2c]
    2021-11-09 07:30:49 [ℹ]  subnets for us-east-2b - public:192.168.0.0/19 private:192.168.96.0/19
    2021-11-09 07:30:49 [ℹ]  subnets for us-east-2a - public:192.168.32.0/19 private:192.168.128.0/19
    2021-11-09 07:30:49 [ℹ]  subnets for us-east-2c - public:192.168.64.0/19 private:192.168.160.0/19
    2021-11-09 07:30:49 [!]  Custom AMI detected for nodegroup ng-1. Please refer to https://github.com/weaveworks/eksctl/issues/3563 for upcoming breaking changes
    2021-11-09 07:30:49 [ℹ]  nodegroup "ng-1" will use "ami-027c737021be27497" [Ubuntu2004/1.20]
    2021-11-09 07:30:50 [ℹ]  using SSH public key "/home/aws/.ssh/id_rsa.pub" as "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1-03:fb:f9:0e:5a:56:13:1e:a4:d6:ab:7e:f3:b2:83:81"
    2021-11-09 07:30:51 [ℹ]  using Kubernetes version 1.20
    2021-11-09 07:30:51 [ℹ]  creating EKS cluster "demo2-kubearmor-ub20" in "us-east-2" region with un-managed nodes
    2021-11-09 07:30:51 [ℹ]  1 nodegroup (ng-1) was included (based on the include/exclude rules)
    2021-11-09 07:30:51 [ℹ]  will create a CloudFormation stack for cluster itself and 1 nodegroup stack(s)
    2021-11-09 07:30:51 [ℹ]  will create a CloudFormation stack for cluster itself and 0 managed nodegroup stack(s)
    2021-11-09 07:30:51 [ℹ]  if you encounter any issues, check CloudFormation console or try 'eksctl utils describe-stacks --region=us-east-2 --cluster=demo2-kubearmor-ub20'
    2021-11-09 07:30:51 [ℹ]  CloudWatch logging will not be enabled for cluster "demo2-kubearmor-ub20" in "us-east-2"
    2021-11-09 07:30:51 [ℹ]  you can enable it with 'eksctl utils update-cluster-logging --enable-types={SPECIFY-YOUR-LOG-TYPES-HERE (e.g. all)} --region=us-east-2 --cluster=demo2-kubearmor-ub20'
    2021-11-09 07:30:51 [ℹ]  Kubernetes API endpoint access will use default of {publicAccess=true, privateAccess=false} for cluster "demo2-kubearmor-ub20" in "us-east-2"
    2021-11-09 07:30:51 [ℹ]
    2 sequential tasks: { create cluster control plane "demo2-kubearmor-ub20",
        2 sequential sub-tasks: {
            wait for control plane to become ready,
            create nodegroup "ng-1",
        }
    }
    2021-11-09 07:30:51 [ℹ]  building cluster stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:30:52 [ℹ]  deploying stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:31:22 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:31:54 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:32:55 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:33:56 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:34:57 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:35:58 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:36:59 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:38:00 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:39:01 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:40:02 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:41:03 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:42:04 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-cluster"
    2021-11-09 07:44:11 [ℹ]  building nodegroup stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:44:11 [!]  Custom AMI detected for nodegroup ng-1, using legacy nodebootstrap mechanism. Please refer to https://github.com/weaveworks/eksctl/issues/3563 for upcoming breaking changes
    2021-11-09 07:44:11 [ℹ]  --nodes-min=1 was set automatically for nodegroup ng-1
    2021-11-09 07:44:11 [ℹ]  --nodes-max=1 was set automatically for nodegroup ng-1
    2021-11-09 07:44:12 [ℹ]  deploying stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:44:12 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:44:29 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:44:47 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:45:07 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:45:25 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:45:46 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:46:06 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:46:26 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:46:44 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:47:03 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:47:20 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:47:37 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:47:57 [ℹ]  waiting for CloudFormation stack "eksctl-demo2-kubearmor-ub20-nodegroup-ng-1"
    2021-11-09 07:47:58 [ℹ]  waiting for the control plane availability...
    2021-11-09 07:47:58 [✔]  saved kubeconfig as "/home/aws/.kube/config"
    2021-11-09 07:47:58 [ℹ]  no tasks
    2021-11-09 07:47:58 [✔]  all EKS cluster resources for "demo2-kubearmor-ub20" have been created
    2021-11-09 07:47:59 [ℹ]  adding identity "arn:aws:iam::199488642388:role/eksctl-demo2-kubearmor-ub20-nodeg-NodeInstanceRole-1AQF5DSREK44B" to auth ConfigMap
    2021-11-09 07:48:00 [ℹ]  nodegroup "ng-1" has 0 node(s)
    2021-11-09 07:48:00 [ℹ]  waiting for at least 1 node(s) to become ready in "ng-1"
    2021-11-09 07:49:32 [ℹ]  nodegroup "ng-1" has 1 node(s)
    2021-11-09 07:49:32 [ℹ]  node "ip-192-168-82-227.us-east-2.compute.internal" is ready
    2021-11-09 07:49:34 [ℹ]  kubectl command should work with "/home/aws/.kube/config", try 'kubectl get nodes'
    2021-11-09 07:49:34 [✔]  EKS cluster "demo2-kubearmor-ub20" in "us-east-2" region is ready
    ```
  </details>

#### 3. Deploying KubeArmor

- Follow the [deployment guide](../../getting-started/deployment_guide.md) to install KubeArmor in the cluster.
</details>

## Prerequisites

1. [k3s](../deployments/k3s)
2. [Amazon Elastic Kubernetes Service (EKS)](../deployments/EKS#prerequisite-for-the-deployment)
3. [Minikube](../contribution/minikube#minikube-installation)
