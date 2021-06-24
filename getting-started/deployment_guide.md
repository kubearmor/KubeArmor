# Deployment Guide

  KubeArmor currently supports self-managed Kubernetes and Google Kubernetes Engine \(GKE\). It will support Amazon Elastic Kubernetes Service \(EKS\) and Azure Kubernetes Service \(AKS\) later.  


  According to your environment, you can choose one of the following.  


  * Deploy KubeArmor \(in self-managed Kubernetes and GKE\)

    ```text
      $ cd KubeArmor/deployments/generic
      ~/KubeArmor/deployments/generic$ kubectl apply -f .
    ```

  * Deploy KubeArmor with older Docker

    ```text
      $ cd KubeArmor/deployments/docker
      ~/KubeArmor/deployments/docker$ kubectl apply -f .
    ```

  * Deploy KubeArmor in MicroK8s

    ```text
      $ cd KubeArmor/deployments/microk8s
      ~/KubeArmor/deployments/microk8s$ kubectl apply -f .
    ```

