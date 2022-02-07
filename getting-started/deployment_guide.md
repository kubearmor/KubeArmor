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

## Prerequisites
1. [k3s](../deployments/k3s)
2. [Amazon Elastic Kubernetes Service (EKS)](../deployments/EKS#prerequisite-for-the-deployment)
3. [Minikube](../contribution/minikube#minikube-installation)
