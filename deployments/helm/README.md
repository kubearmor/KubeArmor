## Install KubeArmor

Install KubeArmor using helm

```
helm upgrade --install kubearmor . \
    --set kubearmorrelay.enabled=true \
    --set namespace.name=<namespace> \
    -n <namespace> \
    --set environment.name=<environment>
```
* kubearmorrelay.enabled = {true | false} (default: true)
* namespace.name = [namespace name] (default: kube-system)
* environment.name = {generic | docker | microk8s | minikube | k3s} (default: generic) / use 'generic' for GKE and EKS

Check if all the pods are up and running

```
kubectl get all -n <namespace>
```

## Remove KubeArmor

Uninstall KubeArmor using helm

```
helm uninstall kubearmor -n <namespace>
```
