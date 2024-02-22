# KubeArmor Support Matrix

KubeArmor supports following types of workloads:
1. **K8s orchestrated**: Workloads deployed as k8s orchestrated containers. In this case, Kubearmor is deployed as a [k8s daemonset](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/). Note, KubeArmor supports policy enforcement on both k8s-pods ([KubeArmorPolicy](security_policy_specification.md)) as well as k8s-nodes ([KubeArmorHostPolicy](host_security_policy_specification.md)).
2. **Containerized**: Workloads that are containerized but not k8s orchestrated are supported. KubeArmor installed in [systemd mode] can be used to protect such workloads.
3. **VM/Bare-Metals**: Workloads deployed on Virtual Machines or Bare Metal i.e. workloads directly operating as host/system processes. In this case, Kubearmor is deployed in [systemd mode].

[systemd mode]: kubearmor_vm.md

## Kubernetes Support Matrix

| Provider   | K8s engine   | OS Image    | Arch   | [Observability] | Audit Rules | Blocking Rules | [Network-Segmentation] | LSM Enforcer | Remarks |
|:----------:|:------------:|:-----------:|:------:|:---------------:|:-----------:|:--------------:|:----------------------:|:------------:|:-------:|
| Onprem     | kubeadm, [k0s], [k3s], microk8s | [Distros] | x86_64, ARM | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor |
| Google     | [GKE] | [COS] | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor | All [release channels][GKE-REL] |
| Google     | [GKE] | Ubuntu >= 16.04 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor | All [release channels][GKE-REL] |
| Microsoft  | [AKS] | Ubuntu >= 18.04 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor |
| Oracle     | [OKE] | [UEK] >=7 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] | [Oracle Linux Server 8.7][OLS] |
| IBM        | [IBM k8s Service][IKS] | Ubuntu | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor |
| AWS        | [EKS] | Amazon Linux 2 (kernel >=5.8) | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] |
| AWS        | [EKS] | Amazon Linux 2 (kernel <=5.4) | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :x: | :heavy_check_mark: | SELinux |
| AWS        | [EKS] | Ubuntu | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | AppArmor |
| AWS        | [EKS] | [Bottlerocket] | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] |
| AWS        | [Graviton] | Ubuntu | ARM | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | AppArmor |
| AWS        | [Graviton] | Amazon Linux 2 | ARM | :heavy_check_mark: | :heavy_check_mark: | :x: | :heavy_check_mark: | SELinux |
| RedHat     | [OpenShift] | [RHEL] <=8.4 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :x:  | :heavy_check_mark: | SELinux |
| RedHat     | [OpenShift] | [RHEL] >=8.5 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] |
| RedHat     | [MicroShift] | [RHEL] >=9.2 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] |
| Rancher    | [RKE] | [SUSE] | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor |
| Rancher    | [K3S] | [Distros] | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM], AppArmor |
| Oracle     | [Ampere] | [UEK] | ARM | :heavy_check_mark: | :heavy_check_mark: | :x: | :heavy_check_mark: | SELinux | [1084] |
| VMware     | [Tanzu] | TBD | x86_64 | :construction: | :construction: | :construction: | :construction: | :construction: | [1064] |
| Mirantis     | [MKE] | Ubuntu>=20.04 | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | AppArmor | [1181] |
| Digital Ocean | [DOKS] | Debian GNU/Linux 11 (bullseye) | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] | [1120] |
| Alibaba Cloud | [Alibaba] | Alibaba Cloud Linux 3.2104 LTS | x86_64 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: | [BPFLSM] | [1650] |

[Observability]: workload_visibility.md
[Network-Segmentation]: network_segmentation.md
[GKE]: https://cloud.google.com/kubernetes-engine
[EKS]: https://aws.amazon.com/eks/
[AKS]: https://azure.microsoft.com/
[COS]: https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits
[GKE-REL]: https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels
[bottlerocket]: https://github.com/bottlerocket-os/bottlerocket#bottlerocket-os
[OPENSHIFT]: https://www.redhat.com/en/technologies/cloud-computing/openshift
[MicroShift]: https://microshift.io/
[SUSE]: https://www.suse.com/
[RHEL]: https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux
[RKE]: https://rancher.com/docs/rke/latest/en/
[K0S]: https://k0sproject.io
[K3S]: https://www.rancher.com/products/k3s
[OKE]: https://www.oracle.com/cloud/cloud-native/container-engine-kubernetes/
[UEK]: https://docs.oracle.com/en/operating-systems/uek/
[OLS]: https://docs.oracle.com/en/operating-systems/oracle-linux/8/relnotes8.7/
[IKS]: https://www.ibm.com/cloud/kubernetes-service
[Tanzu]: https://tanzu.vmware.com/kubernetes-grid
[Graviton]: https://aws.amazon.com/ec2/graviton/
[Ampere]: https://www.oracle.com/in/cloud/compute/arm/
[1064]: https://github.com/kubearmor/KubeArmor/issues/1064
[1084]: https://github.com/kubearmor/KubeArmor/issues/1084
[BPFLSM]: https://github.com/kubearmor/KubeArmor/issues/484
[Distros]: #Supported-Linux-Distributions
[MKE]: https://www.mirantis.com/software/mirantis-kubernetes-engine/
[1181]: https://github.com/kubearmor/KubeArmor/issues/1181
[DOKS]: https://www.digitalocean.com/products/kubernetes/
[1120]: https://github.com/kubearmor/KubeArmor/issues/1120
[1650]: https://github.com/kubearmor/KubeArmor/issues/1650
[Alibaba]: https://www.alibabacloud.com/
## Supported Linux Distributions

Following distributions are tested for VM/Bare-metal based installations:

| Provider | Distro | VM / Bare-metal | Kubernetes |
|----------|--------|---------------|------|
| SUSE | SUSE Enterprise 15 | Full | Full |
| Debian | [Buster](https://www.debian.org/releases/buster/) / [Bullseye](https://www.debian.org/releases/bullseye/) | Full | Full |
| Ubuntu | 18.04 / 16.04 / 20.04 | Full | Full |
| RedHat / CentOS | RHEL / CentOS <= 8.4 | Full | Partial |
| RedHat / CentOS | RHEL / CentOS >= 8.5 | Full | Full |
| Fedora | Fedora 34 / 35 | Full | Full |
| Rocky Linux | Rocky Linux >= 8.5 | Full | Full |
| AWS | Amazon Linux 2022 | Full | Full |
| AWS | Amazon Linux 2023 | Full | Full |
| RaspberryPi (ARM) | Debian | Full | Full |
| ArchLinux | ArchLinux-6.2.1   | Full | Full |
| Alibaba | Alibaba Cloud Linux  3.2104 LTS 64 bit  | Full | Full |

> **Note**
> Full: Supports both enforcement and observability  
> Partial: Supports only observability

### Platform I am interested is not listed here! What can I do?

Please approach the Kubearmor community on [slack](https://github.com/kubearmor/kubearmor#slack) or [raise](https://github.com/kubearmor/KubeArmor/issues/new/choose) a GitHub issue to express interest in adding the support.

It would be very much appreciated if you can test kubearmor on a platform not listed above and if you have access to. Once tested you can update this document and raise a PR.

