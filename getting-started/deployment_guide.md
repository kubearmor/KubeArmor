# Deployment Guide

  KubeArmor currently supports self-managed Kubernetes and Google Kubernetes Engine \(GKE\). It will support Amazon Elastic Kubernetes Service \(EKS\) and Azure Kubernetes Service \(AKS\) later.  


  According to your environment, you can choose one of the following.  


  * Deploy KubeArmor in self-managed Kubernetes \(with Docker\)

    ```text
      $ cd deployments/generic-docker
      (generic-docker) $ kubectl apply -f .
    ```

  * Deploy KubeArmor in self-managed Kubernetes \(with Containerd\)

    ```text
      $ cd deployments/generic-containerd
      (generic-containerd) $ kubectl apply -f .
    ```

  * Deploy KubeArmor in MicroK8s

    ```text
      $ cd deployments/microk8s
      (microk8s) $ kubectl apply -f .
    ```

  * Deploy KubeArmor in GKE

    ```text
      $ cd deployments/GKE
      (GKE) $ kubectl apply -f .
    ```

  * Deploy KubeArmor in EKS

    ```text
      Coming soon
    ```

  * Deploy KubeAmor in AKS

    ```text
      Coming soon
    ```

