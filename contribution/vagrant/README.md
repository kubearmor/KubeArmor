# Vagrant Environment

We provide multiple Vagrant VMs for development and testing.

> **Prerequisites & Security Modules:**
> * **AppArmor:** Enabled by default on all **Ubuntu** environments.
> * **SELinux:** Enabled by default on all **CentOS** environments.
> * **BPF-LSM:** To test BPF-LSM enforcement, you **must** use `NETNEXT=1` (Ubuntu 22.04 or CentOS 9) to ensure Kernel version >5.7 is used.

## Vagrant Values

- OS = { centos | ubuntu } (ubuntu by default)
  - If OS == centos
    - NETNEXT = { 0 | 1 } (0 by default)
      - 0: CentOS 8 (Kernel 4.18)
      - 1: CentOS 9 (Kernel 5.14+, Supports BPF-LSM)
  - If OS == ubuntu
    - NETNEXT = { -1 | 0 | 1 } (0 by default)
      - -1: Ubuntu 18.04 (Kernel 4.15)
      - 0: Ubuntu 20.04 (Kernel 5.4)
      - 1: Ubuntu 22.04 (Kernel 5.15+, Supports BPF-LSM)

- K8S = { k3s | kubeadm } (k3s by default)

- RUNTIME = { docker | containerd | crio } (docker by default)

- NODEV = { 0 | 1 } (0 by default)
  - 0: Kubernetes + Development Setup
  - 1: Kubernetes only

## Vagrant VM Management

### 1. Use `vagrant` command directly

You must navigate to the vagrant directory first.

```
$ cd KubeArmor/contribution/vagrant
$ [Vagrant Values] vagrant { up | status | ssh | destroy }
```

**Examples:**

```
$ vagrant up
```
Ubuntu 20.04 + K3s + Docker + Development Setup

```
$ OS=ubuntu NETNEXT=1 vagrant up
```
Ubuntu 22.04 (BPF-LSM) + K3s + Docker + Development Setup

```
$ NETNEXT=-1 vagrant up
```
Ubuntu 18.04 + K3s + Docker + Development Setup

```
$ OS=centos vagrant up
```
CentOS 8 + K3s + Docker + Development Setup

```
$ OS=centos NETNEXT=1 vagrant up
```
CentOS 9 (BPF-LSM) + K3s + Docker + Development Setup

```
$ K8S=kubeadm RUNTIME=containerd vagrant up
```
Ubuntu 20.04 + Kubeadm + Containerd + Development Setup

```
$ NODEV=1 vagrant up
```
Ubuntu 20.04 + K3s + Docker / no Development Setup

### 2. Use `make` command

The `make` command acts as a wrapper, allowing you to run vagrant commands from the KubeArmor directory without manually changing directories.

```
$ cd KubeArmor/KubeArmor
$ make { vagrant-up | vagrant-status | vagrant-ssh | vagrant-destroy } [Vagrant Values]
```

```
$ make vagrant-up
```

```
$ make vagrant-up OS=ubuntu NETNEXT=1
```

```
$ make vagrant-up NETNEXT=-1
```

```
$ make vagrant-up OS=centos
```

```
$ make vagrant-up OS=centos NETNEXT=1
```

```
$ make vagrant-up K8S=kubeadm RUNTIME=containerd
```

```
$ make vagrant-up NODEV=1
```
