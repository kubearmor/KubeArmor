# Deploy KubeArmor on k3s

K3s is a fully CNCF (Cloud Native Computing Foundation) certified, compliant Kubernetes distribution by SUSE (formally Rancher Labs) that is easy to use and focused on been light.

It is designed to be a single binary of about <50MB that completely implements the Kubernetes APIs. To ensure lightness k3s removed a lot of extra drivers that are not strictly part of the core, but still easily replaceable with external add-ons. Moreover, k3s supports ARM64 and ARMv7 architectures.

### k3s Install

```
curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
```

This will install k3s and start a local cluster. Note that `--write-kubeconfig-mode 644` will result in warnings since the kubeconfig is world readable. But since this is a temporary test cluster, there should be no risk. **Please remove this option if you intend to use k3s + kubearmor on a production/staging env**.

Also you might have to set KUBECONFIG if you want to use `kubectl` directly
```
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```
... else you have to use `k3s kubectl <options>`.

Ref: [k3s.io](https://k3s.io/)

## Deploying KubeArmor

Follow the [deployment guide](../../getting-started/deployment_guide.md) to install KubeArmor in the cluster.

## k3s Uninstall

```
/usr/local/bin/k3s-uninstall.sh
```
