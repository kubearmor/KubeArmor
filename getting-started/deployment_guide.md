# Deployment Guide

KubeArmor currently supports the following.

```text
Self-managed Kubernetes. MicroK8s, MiniKube, Google Kubernetes Engine (GKE), EKS (Audit mode only)
```

In order to deploy KubeArmor, please choose one of the below options according to your environment.

* Deploy KubeArmor with newer Docker (19.03) or Containerd on self-managed Kubernetes

  ```text
  $ cd KubeArmor/deployments/generic
  ~/KubeArmor/deployments/generic$ kubectl apply -f .
  ```

* Deploy KubeArmor with older Docker (18.03) on self-managed Kubernetes

  ```text
  $ cd KubeArmor/deployments/docker
  ~/KubeArmor/deployments/docker$ kubectl apply -f .
  ```

* Deploy KubeArmor on GKE

  ```text
  $ cd KubeArmor/deployments/GKE
  ~/KubeArmor/deployments/GKE$ kubectl apply -f .
  ```
  
* Deploy KubeArmor in MicroK8s

  ```text
  $ cd KubeArmor/deployments/microk8s
  ~/KubeArmor/deployments/microk8s$ kubectl apply -f .
  ```

* Deploy KubeArmor in Minikube

  ```text
  $ cd KubeArmor/deployments/minikube
  ~/KubeArmor/deployments/minikube$ kubectl apply -f .
  ```

* Deploy KubeArmor with Docker on SELinux-enabled self-managed Kubernetes

  ```text
  $ cd KubeArmor/deployments/selinux
  ~/KubeArmor/deployments/selinux$ kubectl apply -f .
  ```
  
* Deploy on EKS
[Guide to installing KubeArmor on EKS](eks_guide.md) 

