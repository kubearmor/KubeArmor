# Deploy KubeArmor on EKS

## Prerequisite for the deployment

### Setup AWS credentials on your system
Follow the [Getting started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html "Getting started with Amazon EKS") guide

### Install eksctl
Install eksctl on your local system
```
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin
eksctl version
```

## (Option 1) Create an EKS cluster using Ubuntu 20.04

### Creating a cluster
KubeArmor needs kernel headers installed on each node, so we create an EKS cluster the following configuration

```yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: kubearmor-ub20
  region: us-east-2

nodeGroups:
  - name: ng-1
    amiFamily: "Ubuntu2004"
    desiredCapacity: 1
    ssh:
      allow: true
    preBootstrapCommands:
      - "sudo apt install linux-headers-$(uname -r)"
```

Create it using eksctl

```
eksctl create cluster -f ./eks-config.yaml
```

### Deploying KubeArmor
Deploy KubeArmor using the following yaml file
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/master/deployments/EKS/kubearmor.yaml
```

## (Option 2) Create an EKS cluster using Amazon Linux 2

### Limitation
KubeArmor on RedHat based Linux distributions currently supports the audit mode only, which means that you are not able to enforce security policies while the events related to the policies can be audited.

### Creating a cluster
KubeArmor needs kernel headers installed on each node, so we create an EKS cluster the following configuration

```yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: kubearmor-cluster
  region: us-east-2

nodeGroups:
  - name: ng-1
    desiredCapacity: 2
    ssh:
      allow: true

    preBootstrapCommands:
      - "sudo yum install -y kernel-devel-$(uname --kernel-release)"
```

Create it using eksctl:

```
eksctl create cluster -f ./eks-config.yaml
```

### Deploying KubeArmor
Deploy KubeArmor using the following yaml file
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/master/deployments/EKS/kubearmor.yaml
```
