KubeArmor adds a number of new capabilities in this 0.5 release, including:
* support for BPF-LSM policy enforcement,
* integration with the Kubernetes admission controller, and
* support for the CRI-O container runtime engine.

We’ve expanded platform support to include AWS Bottlerocket and Linux 2 and Microsoft AKS. We’ve also added support for network rules in SELinux, made improvements to the CLI, along with other enhancements and fixes.

# Support for BPF-LSM for policy enforcement
KubeArmor today leverages LSMs such as AppArmor, SELinux for policy enforcement. With v0.5, Kubearmor now integrates with BPF-LSM for pod/container based policy enforcement as well. [BPF-LSM](https://docs.kernel.org/bpf/prog_lsm.html) is a new LSM ([Linux Security Modules](https://github.com/kubearmor/KubeArmor/wiki/Introduction-to-Linux-Security-Modules-(LSMs))) that is introduced in the newer kernels (version > 5.7). BPF-LSM allows Kubearmor to attach bpf-bytecode at LSM hooks. This changes everything, since now with bpf-bytecode kubearmor has access to much richer information/kernel context and it does not have to work within the constraints of SELinux and AppArmor policy language.

<img src="https://user-images.githubusercontent.com/9133227/185108027-28782421-2a53-458d-80a7-b2c7c2d2bbbd.png" width="512">

### What platforms support BPF-LSM?
* Latest images of GKE COS (> 1.22.6-gke.1000 [ref](https://cloud.google.com/kubernetes-engine/docs/release-notes-rapid))
* [AWS Bottlerocket](https://aws.amazon.com/bottlerocket/)
* Latest images of [Amazon Linux 2](https://aws.amazon.com/amazon-linux-2/). _Note: The default Amazon Linux 2 is still at kernel version 5.4 and hence bpf-lsm cannot be used with it._
* Most of the managed cloud platforms are already leveraging latest kernel images in their latest OS images. Detailed information could be found [here](https://github.com/nyrahul/linux-kernel-configs#lsm-support).

In fact in most of the latest kernels, the bpf-lsm config is enabled by default.

Relevant Issues/PRs: [#484](https://github.com/kubearmor/KubeArmor/issues/484), [#741](https://github.com/kubearmor/KubeArmor/pull/741)

### What happens if the OS image supports both AppArmor and BPF-LSM? What will be used for policy enforcement?
If BPF-LSM is available, that takes priority by default. Note that BPF-LSM is a [stackable LSM](https://github.com/kubearmor/KubeArmor/wiki/Introduction-to-Linux-Security-Modules-(LSMs)#stackable-vs-non-stackable-lsms) (unlike AppArmor, SELinux) which means it can be enabled with existing non-stackable LSMs such as AppArmor/SELinux. Thus if for some reason the bpf-lsm enforcer fails, the AppArmor enforcer will be automatically used underneath the hood.

### Is their any change in the `KubeArmorPolicy` construct for BPF-LSM?
No. The [existing constructs](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/security_policy_specification.md) work as it is. This means for the user, there is no change in the way policies have to be specified.

# Support for AWS Bottlerocket 🚀 and Amazon Linux 2 (latest image)

![kubearmor-bottlerocket](https://user-images.githubusercontent.com/9133227/179066384-0376b316-d6ec-45ac-9b57-1e76e83e5fbe.png)

### What security does Bottlerocket offer?
Bottlerocket is a security focussed Linux based Open Source OS from Amazon that is purpose built for container based workloads. The intention with Bottlerocket is to avoid installation of maintenance packages directly as part of host OS and install only bare-minimum host packages that are required to run the containers. Maintenance tools could in turn be installed as containers if necessary.

### How Kubearmor improves on Bottlerocket security?
Bottlerocket uses SELinux to lock down the host and provides some limited inter-container isolation.

KubeArmor provides enhanced security by using BPF-LSM to protect Bottlerocket containers from **within** by limiting system behavior with respect to processes, files, etc. For e.g., a k8s security access token that is mounted within the pod is accessible by default across all the containers. KubeArmor can restrict access to such tokens only for certain processes. Similarly KubeArmor can be used to protect other sensitive information e.g., k8s secrets, x509 certs, within the container. Moreover, KubeArmor can restrict execution of certain binaries within the containers.

<img src="https://user-images.githubusercontent.com/9133227/179067248-ffae6ab9-bdc7-4804-89b2-223a5946ae9f.png" width="1024">

### Want to try out AWS Bottlerocket with KubeArmor?
Here is the [quick start guide](https://github.com/kubearmor/KubeArmor/wiki/KubeArmor-Bottlerocket-OS-deployment-guide).

# KubeArmor now uses k8s admission controller to inject security annotations

KubeArmor depends upon AppArmor, SELinux and the underlying LSMs for security policy enforcement. In the context of k8s, such policies need to be specified as annotations. Before v0.5, Kubearmor used to apply deployment patch to inject such annotations. This resulted in the deployment to be restarted. Furthermore, one cannot apply annotations to pods that are not started as part of deployments.

In v0.5, Kubearmor has started making use of k8s admission controller feature to inject annotations in the pod. This resolves the deployment restart issue as well as the annotations can now be applied to pods as well.

<img src="https://user-images.githubusercontent.com/9133227/178907616-58d19959-dd5c-4de2-96c8-40980401f769.png" width="512">

The detailed design document can be found [here](https://github.com/kubearmor/KubeArmor/wiki/Annotation-controller).

Relevant issues/PRs: [#360](https://github.com/kubearmor/KubeArmor/issues/360), [#687](https://github.com/kubearmor/KubeArmor/pull/687), [#655](https://github.com/kubearmor/KubeArmor/pull/655)

# Support for CRI-O
KubeArmor directly interfaces with container runtimes to get metadata like container’s namespaces, image and so on. This metadata is then used for generating rich telemetry data and policy enforcement.

In the past, KubeArmor has supported Containerd and Docker and now with v0.5, KubeArmor will also support the CRI-O runtime. This has been made possible by leveraging the [CRI-API](https://github.com/kubernetes/cri-api). Also, if you have multiple container runtimes, you can now use the CRI_SOCKET environment var or the -criSocket flag with kubearmor for specifying one to use.

<img src="https://user-images.githubusercontent.com/9133227/178956254-521e042a-9428-42b7-82db-57b07877902d.png" width="512">

Relevant Issues/PRs: [#697](https://github.com/kubearmor/KubeArmor/pull/697)

# Support for Microsoft AKS

<img src="https://user-images.githubusercontent.com/9133227/179068652-eb2bacd7-10cb-4429-8bea-55d7e44350b6.png" width="256">

KubeArmor now supports Microsoft AKS and has been validated with the default OS images used on AKS.

Relevant PRs: [#721](https://github.com/kubearmor/KubeArmor/pull/721)

# Network rules support for SELinux

Kubearmor [process-bound network rules](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/security_policy_specification.md#network) allows one to limit network communication to only certain processes. It is possible to enable/disable TCP/UDP/ICMP communication for certain processes only.

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: ksp-block-curl-tcp
spec:
  severity: 8
  selector:
    matchLabels:
      kubernetes.io/hostname: gcp-host-tunnel
  network:
    matchProtocols:
    - protocol: tcp
      fromSource:
        - path: /usr/bin/curl
  action:
    Block
```
The above policy prevents `/usr/bin/curl` from initiating tcp connection.

SELinux support was added as part of v0.4.4 but could not handle the [network based rules]. v0.5 adds support for network based rules.

# Improvements to kubearmor cli tool
[Kubearmor client tool](https://github.com/kubearmor/kubearmor-client) can be used to install, uninstall, watch alerts/telemetry, observe and discover kubearmor security policies. The client tool automatically identifies the underlying k8s/container platform and appropriates handles the deployment. The same client tool can be used across any deployment mode (viz, k8s, pure-containerized and VM/Bare-metal).

Kubearmor client tool was extended to support different filtering options based on process name, resource type, namespace, labels etc. This filtering implementation was handled by a LFX mentee and is documented [here](https://sach1n.medium.com/lfx-mentorship-and-me-5bda26594f63).
