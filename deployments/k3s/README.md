# Deploy KubeArmor on k3s

### Install k3s

```
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
```

This will install k3s and start a local cluster. Note that `--write-kubeconfig-mode 644` will result in warnings since the kubeconfig is world readable now. But since this is a temporary test cluster, there should be no risk. Please remove this option if you intend to use k3s + kubearmor on a production/staging env.

Also you might have to set KUBECONFIG if you want to use kubectl directly
```
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```
... else you have to use `k3s kubectl <options>`.

Ref: [k3s.io](https://k3s.io/)

## Deploying KubeArmor

Follow the [deployment guide](../../getting-started/deployment_guide.md) to install KubeArmor in the cluster.
