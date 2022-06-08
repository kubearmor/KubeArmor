# Deploy KubeArmor on AKS

## 1. Creating an AKS cluster

- Create a Linux-based AKS cluster

	Follow the [Quickstart guide using Azure portal](https://docs.microsoft.com/en-us/azure/aks/learn/quick-kubernetes-deploy-portal)

	Note that KubeArmor doesn't work with Windows-based based AKS clusters as it leverages Linux kernel primitives.

- Set up AKS credentials

	Follow the [connect to your cluster using Azure CLI guide](https://docs.microsoft.com/en-us/azure/aks/learn/quick-kubernetes-deploy-cli#connect-to-the-cluster) to setup AKS credentials on your system so that kubectl and [karmor](https://github.com/kubearmor/kubearmor-client) can connect with your cluster.

## 2. Deploying KubeArmor

- Follow the [deployment guide](../../getting-started/deployment_guide.md) to install KubeArmor in the cluster.
