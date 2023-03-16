# Getting Started Guide

If you do not have a k8s cluster, check the [pre-requisites](#prerequisites) to setup one.

If you want to try KubeArmor directly on the host without k8s, [run KubeArmor in systemd mode](kubearmor_vm.md).

Check the [KubeArmor support matrix](support_matrix.md) to verify if your platform is supported.

## Deployment Steps

### 1. Download and install karmor cli-tool
```
curl -sfL http://get.kubearmor.io/ | sudo sh -s -- -b /usr/local/bin
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

#### Observing logs using karmor cli
```
karmor logs
```

## K8s platforms tested
1. Self-managed (on-prem) k8s
2. Local k8s engines (k3s, microk8s, and minikube)
3. Google Kubernetes Engine (GKE) with Container Optimized OS (COS)
4. GKE with Ubuntu image
5. [Amazon Elastic Kubernetes Service (EKS)](../deployments/EKS)
6. [Azure Kubernetes Service (AKS)](../deployments/AKS)

## Prerequisites
1. [K3s](../deployments/k3s)
2. [MicroK8s](../contribution/microk8s)
3. [Minikube](../contribution/minikube)
4. [Self-managed K8s](../contribution/self-managed-k8s)
5. [Amazon Elastic Kubernetes Service (EKS)](../deployments/EKS#prerequisite-for-the-deployment)
