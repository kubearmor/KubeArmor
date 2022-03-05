## Install KubeArmor using helm
* Install kubearmor via helm, enable/disable kuberarmor relay by specifying either true or false.
* Specify the namespace.
* Specify environment depends on your environment like { docker, microk8s, minikube, k3s and generic (GKE, EKS)} by default it is generic.

```
helm upgrade --install kubearmor . \
    --set kubearmorrelay.enabled=true \
    --set environment.name=<environment> \
    --set namespace.name=<namespace>

```
Check if all the pods are up and running.
```
kubectl get all -n <namespace>
```

## To uninstall KubeArmor using helm
```
helm uninstall kubearmor
```