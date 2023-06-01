## Install KubeArmor

Install KubeArmor using helm

```
helm upgrade --install kubearmor . --set kubearmorRelay.enabled=true -n kube-system
```
* [kubearmorRelay](https://github.com/kubearmor/kubearmor-relay-server/).enabled = {true | false} (default: true)

## Verify if all the pods are up and running

```
kubectl get all -n kube-system
```

## Remove KubeArmor

Uninstall KubeArmor using helm

```
helm uninstall kubearmor -n kube-system
```
