# Deployment Guide

KubeArmor currently supports the following.

```text
Self-managed Kubernetes. MicroK8s, MiniKube, Google Kubernetes Engine (GKE), Amazon Elastic Kubernetes Service (EKS)
```

In order to deploy KubeArmor, please choose one of the below options according to your environment.

* Deploy KubeArmor on Self-managed Kubernetes with newer Docker (19.03) Containerd

  ```text
  $ cd KubeArmor/deployments/generic
  ~/KubeArmor/deployments/generic$ kubectl apply -f .
  ```

* Deploy KubeArmor on Self-managed Kubernetes with older Docker (18.09), Minikube

  ```text
  $ cd KubeArmor/deployments/docker
  ~/KubeArmor/deployments/docker$ kubectl apply -f .
  ```

* Deploy KubeArmor on SELinux-enabled self-managed Kubernetes with Docker

  ```text
  $ cd KubeArmor/deployments/selinux
  ~/KubeArmor/deployments/selinux$ kubectl apply -f .
  ```

* Deploy KubeArmor on MicroK8s

  ```text
  $ cd KubeArmor/deployments/microk8s
  ~/KubeArmor/deployments/microk8s$ kubectl apply -f .
  ```

* Deploy KubeArmor on GKE

  ```text
  $ cd KubeArmor/deployments/GKE
  ~/KubeArmor/deployments/GKE$ kubectl apply -f .
  ```
  
* Deploy KubeArmor on EKS

[Guide to installing KubeArmor on EKS](eks_guide.md) 
