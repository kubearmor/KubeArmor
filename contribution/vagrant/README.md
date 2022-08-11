# Vagrant Environment

We provide multiple Vagrant VMs for development and testing.

## Vagrant Values

- OS = { centos | ubuntu } (ubuntu by default)
    - If OS == centos
        - NETNEXT = { 0 | 1 } (0 by default)
            - 0: CentOS 8, 1: CentOS 9
    - If OS == ubuntu
        - NETNEXT = { -1 | 0 | 1 } (0 by default)
            - -1: Ubuntu 18.04, 0: Ubuntu 20.04, 1: Ubuntu 22.04

- K8S = { k3s | kubeadm } (k3s by default)

- RUNTIME = { docker | containerd | crio } (docker by default)

- NODEV = { 0 | 1 } (0 by default)
    - 0: Kubernetes + Development Setup, 1: Kubernetes only

## Vagrant VM Management

- Use 'vagrant' command directly

```
$ cd KubeArmor/contribution/vagrant
$ [Vagrant Values] vagrant { up | status | ssh | destroy }
```

```
$ vagrant up -> Ubuntu 20.04 + K3s + Docker + Development Setup
$ OS=ubuntu NETNEXT=1 vagrant up -> Ubuntu 22.04 + K3s + Docker + Development Setup
$ NETNEXT=-1 vagrant up -> Ubuntu 18.04 + K3s + Docker + Development Setup
$ OS=centos vagrant up -> CentOS 8 + K3s + Docker + Development Setup
$ K8S=kubeadm RUNTIME=containerd vagrant up -> Ubuntu 20.04 + Kubeadm + Containerd + Development Setup
$ NODEV=1 vagrant up -> Ubuntu.20.04 + K3s + Docker / no Development Setup
```

- Use 'make' command

```
$ cd KubeArmor/KubeArmor
$ make { vagrant-up | vagrant-status | vagrant-ssh | vagrant-destroy } [Vagrant Values]
```

```
$ make vagrant-up
$ make vagrant-up OS=ubuntu NETNEXT=1
$ make vagrant-up NETNEXT=-1
$ make vagrant-up OS=centos
$ make vagrant-up K8S=kubeadm RUNTIME=containerd
$ make vagrant-up NODEV=1
```
