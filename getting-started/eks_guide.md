# Deploy KubeArmor on EKS

## Limitations
KubeArmor on EKS currently only supports audit mode, you will not be able to enforce rules. But those events would be logged.

## Create an EKS cluster

### Setup AWS credentials on your system
You can follow the [Getting started with Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html "Getting started with Amazon EKS") Guide 

### Install EKS
Install eksctl on your local system
```
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin
eksctl version
```

### Creating the cluster
KubeArmor needs kernel headers installed on the node in order to run. So we create an EKS cluster the following config:
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

## Deploying KubeArmor
Then we deploy this using the docker yaml
```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/master/deployments/docker/kubearmor.yaml
```
