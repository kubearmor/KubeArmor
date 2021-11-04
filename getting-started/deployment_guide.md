# Deployment Guide

## Deployment Steps
### 1. Download and install karmor cli-tool
```
curl -sfL https://raw.githubusercontent.com/kubearmor/kubearmor-client/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

### 2. Install KubeArmor
```
karmor install
```
It is assumed that the k8s cluster is already present/reachable and the user has rights to create service-accounts and cluster-role-bindings.

### 3. Deploying sample app and policies
   
#### a. Deploy sample [multiubuntu app](https://github.com/kubearmor/KubeArmor/blob/master/examples/multiubuntu.md)
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/master/examples/multiubuntu/multiubuntu-deployment.yaml
```
#### b. Deploy [sample policies](https://github.com/kubearmor/KubeArmor/blob/master/getting-started/security_policy_examples.md)
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/master/examples/multiubuntu/security-policies/ksp-group-1-proc-path-block.yaml
```
This sample policy blocks execution of `sleep` command in ubuntu-1 pods.
#### c. Simulate policy violation
```
$ kubectl -n multiubuntu exec -it POD_NAME_FOR_UBUNTU_1 -- bash
# sleep 1
(Permission Denied)
```
Substitute POD_NAME_FOR_UBUNTU_1 with the actual pod name from `kubectl get pods -n multiubuntu`.

### 4. Getting Alerts/Telemetry from KubeArmor
#### a. Enable port-forwarding for KubeArmor relay
```
kubectl port-forward -n kube-system svc/kubearmor 32767:32767
```
#### b. Observing logs using karmor cli
```
karmor log
```

## K8s platforms tested
1. Google Kubernetes Engine (GKE) Container Optimized OS (COS)
2. GKE Ubuntu image
3. [Amazon Elastic Kubernetes Service (EKS)](https://github.com/kubearmor/KubeArmor/tree/master/deployments/EKS)
4. Self-managed (on-prem) k8s
5. Local k8s engines (microk8s, k3s, minikube)

