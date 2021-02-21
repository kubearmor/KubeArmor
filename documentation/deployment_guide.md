# Deployment Guide

1. Deploy a custom resource definition for security policies

   Kubernetes cannot recognize the specification of security policies for KubeArmor unless you register the custom resource definition for KubeArmor's security policy. Thus, you first need to apply the custom resource definition for KubeArmor's security policy into Kubernetes.

   ```text
    $ cd deployments/CRD
    (deployments/CRD) $ kubectl apply -f .
   ```

2. Deploy KubeArmor in your Kubernetes environment

   KubeArmor currently supports self-managed Kubernetes and Google Kubernetes Engine \(GKE\). It will support Amazon Elastic Kubernetes Service \(EKS\) and Azure Kubernetes Service \(AKS\) later.

   * Deploy KubeArmor in self-managed Kubernetes \(with Docker\)

     ```text
       $ cd deployments/generic-docker
       (deployments/generic-docker) $ kubectl apply -f .
     ```

   * Deploy KubeArmor in self-managed Kubernetes \(with Containerd\)

     ```text
       $ cd deployments/generic-containerd
       (deployments/generic-containerd) $ kubectl apply -f .
     ```

   * Deploy KubeArmor in MicroK8s

     ```text
       $ cd deployments/microk8s
       (deployments/microk8s) $ kubectl apply -f .
     ```

   * Deploy KubeArmor in GKE

     ```text
       $ cd deployments/GKE
       (deployments/GKE) $ kubectl apply -f .
     ```

   * Deploy KubeArmor in EKS

     ```text
       Coming soon
     ```

   * Deploy KubeAmor in AKS

     ```text
       Coming soon
     ```
