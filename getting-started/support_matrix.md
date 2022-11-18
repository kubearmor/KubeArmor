# KubeArmor Support Matrix

KubeArmor supports following types of workloads:
1. K8s orchestrated workloads: Workloads deployed as k8s orchestrated containers. In this case, Kubearmor is deployed as a [k8s daemonset](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/). Note, KubeArmor supports policy enforcement on both k8s-pods ([KubeArmorPolicy](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/security_policy_specification.md)) as well as k8s-nodes ([KubeArmorHostPolicy](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/host_security_policy_specification.md)).
2. VM/Bare-Metals workloads: Workloads deployed on Virtual Machines or Bare Metal i.e. workloads directly operating as host processes. In this case, Kubearmor is deployed in [systemd mode](kubearmor_vm.md).

## K8s support matrix
| Kubernetes Engine | OS Image | Support | Remarks |
|-------------------|-----------|-----------|---------|
| [Google GKE](https://cloud.google.com/kubernetes-engine) | [Container Optimized OS](https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits) | Yes | Supported across Stable/Regular/Rapid/ release channels |
| [Google GKE](https://cloud.google.com/kubernetes-engine) | Ubuntu | Yes | Supported across Stable/Regular/Rapid/ release channels |
| [Microsoft Azure](https://azure.microsoft.com/) | Ubuntu | Yes |
| [AWS EKS](https://aws.amazon.com/eks/) | Amazon Linux 2 (kernel version 5.4) | Partial | Observability/Audit mode is supported, Enforcement mode is supported for nodes/hosts only (not for k8s pods). |
| [AWS EKS](https://aws.amazon.com/eks/) | Amazon Linux 2 (kernel version >5.7) | Yes | Support leveraging [BPF LSM](https://github.com/kubearmor/KubeArmor/issues/484) |
| [AWS EKS](https://aws.amazon.com/eks/) | Ubuntu | Yes |
| [AWS EKS](https://aws.amazon.com/eks/) | [Bottlerocket OS](https://github.com/bottlerocket-os/bottlerocket#bottlerocket-os) | Yes | Support leveraging [BPF LSM](https://github.com/kubearmor/KubeArmor/issues/484)
| RedHat OpenShift | Red Hat Enterprise Linux release 8.4 | Partial | Observability/Audit mode is supported, Enforcement mode is not supported. (Kernel Version: 4.18.0-305.45.1.el8_4.x86_64, Openshift Version: 4.10.14)
| [Rancher RKE](https://www.rancher.com/products/rke) | all | Yes | Supported - Except [RKE deployed on host using a Docker container](https://rancher.com/docs/rancher/v2.5/en/installation/other-installation-methods/single-node-docker/) |
| VMWare Tanzu | * | TBD |
| Nutanix | * | TBD |

## Supported Linux Distributions

| Provider | Distro | VM / Bare-metal | Kubernetes |
|----------|--------|---------------|------|
| SUSE | SUSE Enterprise 15 | Full | Full |
| Debian | [Buster](https://www.debian.org/releases/buster/) / [Bullseye](https://www.debian.org/releases/bullseye/) | Full | Full |
| Ubuntu | 18.04 / 20.04 | Full | Full |
| RedHat / CentOS | RHEL 8.4 / CentOS 8.4 | Full | Partial |
| RedHat | RHEL 9 / RHEL >= 8.5 / CentOS 8 Steam | Full | Full |
| Fedora | Fedora 34 / 35 | Full | Full |
| Rocky Linux | Rocky Linux >= 8.5 | Full | Full |

> **Note**  
> Full: Supports both enforcement and observability  
Partial: Supports only observability

### When will EKS with Amazon Linux 2 be supported?

Amazon Linux 2 currently is shipped with SELinux as the LSM (Linux Security Module). KubeArmor supports SELinux only for host-based policy enforcement. On Amazon Linux 2, Kubearmor currently supports observability/policy audits using ebpf based engine.

The latest versions of Amazon Linux 2 ship with a new LSM type called BPF-LSM and Kubearmor [intends](https://github.com/kubearmor/KubeArmor/issues/484) to support it soon).

### Platform I am interested is not listed here! What can I do?

Please approach the Kubearmor community on [slack](https://github.com/kubearmor/kubearmor#slack) or [raise](https://github.com/kubearmor/KubeArmor/issues/new/choose) a GitHub issue to express interest in adding the support.

It would be very much appreciated if you can test kubearmor on a platform not listed above and if you have access to. Once tested you can update this document and raise a PR, if possible.

### What local K8s platforms are supported?

[Minikube](../contribution/minikube), [K3s](../deployments/k3s) and [Microk8s](../contribution/microk8s) platforms are currently supported.

### Why KubeArmor does not work on kind

KubeArmor does not support Kubernetes in Docker.

