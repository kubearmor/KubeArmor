# Deployment Guide

KubeArmor currently supports the following.

```text
Self-managed Kubernetes. MicroK8s, Google Kubernetes Engine (GKE)
```

In order to deploy KubeArmor, please choose one of the below options according to your environment.

* Deploy KubeArmor on Self-managed Kubernetes with Docker 19.03 or above, Containerd

  ```text
  $ cd KubeArmor/deployments/generic
  ~/KubeArmor/deployments/generic$ kubectl apply -f .
  ```

* Deploy KubeArmor on Self-managed Kubernetes with Docker 18.09 or above

  ```text
  $ cd KubeArmor/deployments/docker
  ~/KubeArmor/deployments/docker$ kubectl apply -f .
  ```

* Deploy KubeArmor in MicroK8s

  ```text
  $ cd KubeArmor/deployments/microk8s
  ~/KubeArmor/deployments/microk8s$ kubectl apply -f .
  ```

* Deploy KubeArmor on GKE

  ```text
  $ cd KubeArmor/deployments/GKE
  ~/KubeArmor/deployments/GKE$ kubectl apply -f .
  ```
