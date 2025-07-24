# Using KubeArmor with OCI Hooks

KubeArmor supports integration with container runtimes via OCI hooks. This document describes how to enable and use OCI hooks with KubeArmor without mounting the container runtime socket into KubeArmor daemonset pods.

Note :- 
1. Currently only CRI-O and Containerd are supported when using OCI hooks with KubeArmor.
2. This feature is currently in experimental stage.

## Table of Contents

#### Overview

#### CRI-O Setup

#### Containerd (via NRI) Setup

#### FAQs

## Overview

OCI hooks allow KubeArmor to monitor and act on container events by executing a hook binary during container lifecycle events.

## CRI-O Setup

### 🛠️ Steps

#### Deploy KubeArmor

Install KubeArmorOperator using the official `kubearmor` Helm chart repo with OCI Hooks enabled.

```bash
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace --set enableOCIHooks=true
```

## Containerd via NRI Setup

### ⚠️ Requirements

* Containerd must be running with containerd v2 API (i.e., containerd-shim-runc-v2).

* NRI (Node Resource Interface) must be enabled.

* The user must deploy the hook-injector plugin on every node.

* Make sure `Go` is installed on your node.

### 🛠️ Steps

#### Ensure NRI is enabled on each node:

```bash
ls -l /var/run/nri/nri.sock

OR

ls -l /run/nri/nri.sock
```

#### Deploy the hook-injector plugin:

The hook injector plugin from NRI (https://github.com/containerd/nri/tree/main/plugins/hook-injector) allows containerd to execute hook binary on container lifecycle events.

* Note :- The steps below are to be performed on each node.

1. `git clone https://github.com/containerd/nri`

2. `cd nri/plugins/hook-injector/`

3. `go build`

4. `./hook-injector -idx 10&`

#### Deploy KubeArmor

Install KubeArmorOperator using the official `kubearmor` Helm chart repo with OCI Hooks enabled.

```bash
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace --set enableOCIHooks=true
```

## FAQs

❓ Why not mount the CRI socket?

Mounting /run/containerd/containerd.sock or /var/run/crio/crio.sock into containers introduces security risks. Exposes container runtime internals to the container. Breaks container isolation. OCI hooks allow us to preserve security and still receive container events.

❓ Can I use OCI hooks with Docker?

No. Docker does not support the OCI hook standard out of the box. We currently support only CRI-O and containerd (with NRI).

❓ Do I need to restart nodes after setting up hooks?

No.