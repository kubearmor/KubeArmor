# KubeArmor v0.9 Release Notes

## New Managed Kubernetes platforms supported

KubeArmor v0.9 added support for new managed kubernetes platforms such as [Oracle Container Engine for Kubernetes (OKE)](https://github.com/kubearmor/KubeArmor/wiki/KubeArmor-support-for-Oracle-Container-Engine-for-Kubernetes-(OKE)), [IBM Cloud Kubernetes Service](https://github.com/kubearmor/KubeArmor/issues/1107), and [AWS Amazon Linux 2](https://github.com/kubearmor/KubeArmor/issues/1005).

<img src="https://user-images.githubusercontent.com/9133227/224011901-55874a44-3a96-43f6-8643-a5b0e616f45e.png" width="768" class="center" alt="KubeArmor Support Matrix">

## Support for ARM based k8s platforms

Support for ARM based cloud platforms such as [AWS Graviton](https://github.com/kubearmor/KubeArmor/issues/1063), and [Oracle Ampere](https://github.com/kubearmor/KubeArmor/issues/1084) are added in v0.9.

<img src="https://user-images.githubusercontent.com/9133227/224018007-e9b644b2-7eb1-45eb-a20c-280fcf9f9648.png" width="768" class="center" alt="graviton and ampere">

Check out full [KubeArmor support matrix here](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/support_matrix.md).

## Performance Improvements

KubeArmor in-kernel event filtering changes were added in v0.9. The intention was to filter the events early in its cycle i.e., in the kernel space itself such that performance penalty of user space context switch is not incurred. Note that KubeArmor uses existing LSM (Linux Security Modules) hooks for policy enforcement. The LSM hooks are already enabled by default in all the Linux kernel images. Overall based on the [benchmarking data](https://github.com/kubearmor/KubeArmor/wiki/KubeArmor-Performance-Benchmarking-Data) taken on the docker sock-shop example, we found that the impact of KubeArmor is <3% on the overall requests per second performance of the sock-shop example.

<img src="https://user-images.githubusercontent.com/9133227/224029506-027de93b-4994-457f-9813-6d22e28640c0.png" width="768" class="center" alt="kubearmor performance">

## Visibility/Telemetry configuration per namespace

Before v0.9, KubeArmor enabled telemetry across all the namespaces, deployments within the cluster. This caused significant telemetry events generated across non-user workload namespaces (such as kube-system). With v0.9, one can selectively enable process, file, network related telemetry across different namespaces.

<img src="https://user-images.githubusercontent.com/9133227/224036523-0cb1aff2-aca1-4aaa-a608-a9c1fd751347.png" width="768" class="center" alt="namespace based visibility">

## K8s Operator-based install for KubeArmor

KubeArmor supports multiple modes of deployment today, including using manifests files, helm, and using karmor cli tool.

However, operator-based installation was desired for KubeArmor for the following reasons:
1. To handle the scenario where the cluster contains multiple nodes supporting different LSM (Linux Security Modules). KubeArmor cannot set the AppArmor annotation in context to the workload deployed on the node not supporting AppArmor.
2. There are certain services such as Kubearmor relay whose resource utilization depends on the number of nodes operating within the cluster.

Operator-based installation and subsequent monitoring simplify the handling of such scenarios.

With this release, the karmor cli tool or the helm/manifests will install the operator and then the operator will install the relevant Daemonset and services needed.

<img src="https://user-images.githubusercontent.com/9133227/224039945-6ea76ca8-c23e-4f72-b0a1-507ae92dc8c4.png" width="512" class="center">

## Consolidation of controllers

KubeArmor installed different controllers each for `KubearmorPolicy`, `KubearmorHostPolicy` in different pods namely `policy-controller` and `host-policy-controller` respectively. The new release consolidates multiple controllers into a single pod reducing the overall number of kubearmor pods deployed in the cluster and that single pod will reconcile all the kubernetes resources managed by KubeArmor.

## Support for Unbreakable Enterprise Linux (UEK) used in Oracle Kubernetes Engine (OKE)

KubeArmor BPFLSM enforcer is used to support OKE with UEK7 and above. KubeArmor BPFLSM didn't support containerd which was a prerequisite for OKE platform. v0.9 added support for containerd to be used with BPFLSM enforcer, thus making OKE work.

## Support for AWS Amazon Linux 2

AWS Amazon Linux 2 kernel version >=5.8 supported BPFLSM, however, it was found that the bpf filesystem was not mounted by default in the worker nodes. KubeArmor added the logic to check if the bpf filesystem is mounted and if not, mount the bpf filesystem on a custom path within the KubeArmor pod itself.

## Support for IBM Cloud Kubernetes Service

IBM Cloud Kubernetes Service by default using Ubuntu 18.04 and AppArmor was by default supported on that platform. Thus KubeArmor didn't had to make any changes to support IBM Cloud Kubernetes Service.

## ARM Servers: Support for AWS Graviton

[AWS Graviton](https://aws.amazon.com/ec2/graviton/) processors are designed by AWS to deliver the best price performance for the cloud workloads running in Amazon EC2. EKS also supports using EC2 instances running on AWS Graviton. AWS Graviton can use any Linux distributions. KubeArmor was tested on Ubuntu and Amazon Linux 2 distributions on AWS Graviton. KubeArmor now support AWS Graviton platform for application behavior analysis, network-segmentation, and audit based policies.

## ARM Servers: Support for Oracle Ampere

The [Oracle Cloud Infrastructure Ampere Altra A1 compute platform](https://www.oracle.com/in/cloud/compute/arm/) provides deterministic performance, linear scalability, and a secure architecture with the best price-performance in the market. Users can leverage the industry’s first 160-core Arm server at only $0.01 per core hour and flexible virtual machines with 1-80 cores and 1-64 GB of memory per core. KubeArmor now support Oracle Ampere platform for application behavior analysis, network-segmentation, and audit based policies.

## Miscellaneous

* **Full Enforcement on BPF LSM with Path based hooks**. BPF-LSM based enforcement lacked certain enforcement support previously wherein file open related events were handled but a simple inode creation events were not handled. This resulted in certain operations (such as `touch`) to succeed even if the path is marked as blocked.

* **Support for mount/umount system calls**: To achieve CIS compliance 4.1.14 Ensure successful file system mounts are collected we need to audit the mount and umount events happening. Currently we are making use of mount and umount binaries for generating KubeArmor policies.
This method will be not effective if the attacker is trying mount or unmount using system calls. KubeArmor now supports the mount/umount syscalls to make sure that issue mentioned is solved.

* **App Behavior fixes**: Bind port data is now showing meaningful data. Removed unnecessary netlink and unix domain sockets handling in the context.

* **Use of k8s `configmap`**: KubeArmor configuration previously was kept as environment variables. The new release ensures that KubeArmor uses k8s native approach of handling configuration and the changes to the configuration can now be handled dynamically i.e., without restarting the KubeArmor.
