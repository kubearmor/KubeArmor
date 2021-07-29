# Deployment Guide

KubeArmor currently supports self-managed Kubernetes and Google Kubernetes Engine \(GKE\).

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