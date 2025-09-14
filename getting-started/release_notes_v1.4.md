# KubeArmor v1.4.0 Release Blog

[KubeArmor Operator as the Default Installation Method](#kubearmor-operator-as-the-default-installation-method)

[Capabilities Enforcement with BPF LSM](#capabilities-enforcement-with-bpf-lsm)

[Execname Matching in KubeArmor Policies](#execname-matching-in-kubearmor-policies)

[Securing KubeArmor](#securing-kubearmor)

[Additional Columns for KubeArmor Policies](#additional-columns-for-kubearmor-policies)

[Support for Alibaba Cloud](support-for-alibaba-cloud)

[Performance Improvements](#performance-improvements)

## Key Takeaways
- KubeArmor Operator is now the default installation method for KubeArmor, providing a more streamlined installation process.
- New features include support for capabilities enforcement using BPF LSM, execname matching in policies, and additional columns in KubeArmor Security Policies (KSPs) and Host Security Policies (HSPs).
- Security enhancements include securing KubeArmor itself with Seccomp profiles and implementing mutual TLS (mTLS) for secure gRPC communication
- Support for Alibaba Cloud deployments has been added.
- Performance improvements include filtering watched nodes and pods server-side to reduce overhead in large clusters.

### KubeArmor Operator as the Default Installation Method
Earlier we used to install KubeArmor through plain Kubernetes manfiests. In kubearmor-client a.k.a karmor, we had a heurisitics based mechanism for detecting the target environment and create KubeArmor manifests accordingly.
In recent releases we've developed the KubeArmor Operator - a Kubernetes operator which gets the granular per-node configuration of target environments and accordingly creates KubeArmor manifests. We have been pushing on operator based installation, make it more stable and slowly migrating our docs and references to point towards it instead of the old method. Finally, with this release - we now have karmor using the operator based installation too.

**Issues:** https://github.com/kubearmor/KubeArmor/issues/1256

**PRs:** https://github.com/kubearmor/kubearmor-client/pull/402

### Capabilities Enforcement with BPF LSM
In Kubernetes environments, certain workloads may require specific Linux capabilities to function correctly. However, granting unnecessary capabilities can introduce security risks. Previously, KubeArmor had the ability to enforce policies on Linux capabiliites only when using the AppArmor enforcer, recently we've introduced the same in our distinguishing BPF LSM enforcer as well.
This improves the feature parity between AppArmor and BPF-LSM and allows you to define policies that restrict or allow specific capabilities for your workloads, enhancing the overall security posture of your Kubernetes cluster.

**References:** [Restrict Capabilities Usecase](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/use-cases/hardening.md#restrict-capabilities-do-not-allow-capabilities-that-can-be-leveraged-by-the-attacker)

**Issues:**
- https://github.com/kubearmor/KubeArmor/issues/795
- https://github.com/kubearmor/KubeArmor/issues/1538

**PRs:**
- https://github.com/kubearmor/KubeArmor/pull/1543

### Execname Matching in KubeArmor Policies
Identifying and blocking malicious or unauthorized applications running in your Kubernetes cluster can be a challenging task, especially when dealing with dynamic or obfuscated binaries. Previously, KubeArmor relied solely on file paths or other attributes to define policies, limiting its ability to detect and prevent the execution of specific binaries.
To address this limitation, KubeArmor now supports matching executable names in its policies. This new feature enables you to create rules based on the name of the executable binary, allowing for more granular control over the applications running in your Kubernetes cluster. For example, you can now block or allow specific crypto-mining binaries like xmrig by matching their executable names.
By introducing execname matching, KubeArmor provides an additional layer of security and control, enabling you to proactively detect and prevent the execution of known malicious or unauthorized binaries within your Kubernetes environment.

**References:** [Example Policy](https://github.com/kubearmor/KubeArmor/blob/main/tests/k8s_env/ksp/multiubuntu/ksp-ubuntu-1-block-proc-execname.yaml)

**Discussion:** https://kubearmor.slack.com/archives/C01F9V3SEHY/p1709480346589829

**PRs:** https://github.com/kubearmor/KubeArmor/pull/1664

### Securing KubeArmor
As a security project, it's crucial for KubeArmor itself to adhere to security best practices and minimize its attack surface. For this, we've been constantly making improvements through past releases.
In this release
#### Seccomp
KubeArmor will now ship with a default seccomp profile of it's own to restrict the system calls it can make. The profile won't be activated by default as of now but in future releases we'll make it enabled by default.

#### Secure gRPC Communication with Mutual TLS
In previous versions of KubeArmor, communication between the KubeArmor server and clients (e.g., kubearmor-relay, kubearmor-client) was unencrypted, potentially exposing sensitive information or allowing unauthorized access to the communication channel.
To address this security concern, KubeArmor now supports secure gRPC communication between the KubeArmor server and clients using mutual TLS (mTLS). This enhancement ensures that all communication between KubeArmor components is encrypted and only trusted parties can connect with KubeArmor.

#### Vulnerabilities
Many critical vulnerabilities across KubeArmor images have been addressed, ensuring the overall security of the KubeArmor deployment and protecting against potential exploits or vulnerabilities.

**References:** [KubeArmor Security Enhancements](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/kubearmor-security-enhancements.md)

**Issues:** https://github.com/kubearmor/KubeArmor/issues/1186

**PRs:**
- https://github.com/kubearmor/KubeArmor/pull/1526
- https://github.com/kubearmor/KubeArmor/pull/1661

### Additional Columns for KubeArmor Policies
Previously, when listing KubeArmor Security Policies (KSPs) and Host Security Policies (HSPs) using kubectl get, users only had access to limited information about each policy, making it challenging to quickly assess the purpose and impact of each policy.
To improve visibility and usability, policy status now includes additional columns. These columns display the action (Allow/Audit/Block) and severity level for each policy.
This enhancement allows users to quickly identify the intended behavior and potential impact of each policy, facilitating easier policy management and enabling more informed decision-making when deploying or updating security policies within their Kubernetes environment.

**References:**

![image](https://github.com/kubearmor/KubeArmor/assets/54525605/aa7d53e9-d268-4975-a104-3db36a3461ff)

**Issues:** https://github.com/kubearmor/KubeArmor/issues/1326https://github.com/dqsully

**PRs:** https://github.com/kubearmor/KubeArmor/pull/1683

### Support for Alibaba Cloud
As Kubernetes adoption continues to grow, organizations are increasingly leveraging various cloud providers to host their deployments. Previously, KubeArmor lacked official support for Alibaba Cloud deployments, which could pose challenges for users seeking to secure their Kubernetes workloads running on Alibaba Cloud's infrastructure.
To address this gap, KubeArmor now officially supports Alibaba Cloud deployments, including Alibaba Cloud Kubernetes (ACK) and Elastic Compute Services (Virtual Machines). This support ensures that KubeArmor can be seamlessly deployed and integrated with Alibaba Cloud environments, providing robust security for your Kubernetes workloads running on Alibaba Cloud.
With this addition, KubeArmor expands its reach and enables organizations leveraging Alibaba Cloud to benefit from its advanced security capabilities, ensuring consistent protection across various cloud platforms. The latest image of Alibaba Cloud Linux 3 contains BPF-LSM enabled by default as part of the kernel config but not enabled by default as part of the boot parameter. Thus the user has to enable BPF-LSM boot for all the nodes for which they desire to secure with KubeArmor. Checkout the FAQ for [Checking And Enabling Support For BPF LSM](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/FAQ.md#checking-and-enabling-support-for-bpf-lsm).

### Performance Improvements
In large-scale Kubernetes deployments with numerous nodes and pods, the overhead associated with listing and watching all resources can significantly impact performance and scalability. Previously, each KubeArmor DaemonSet pod listed and watched every node and pod in the cluster, leading to potential performance bottlenecks and resource constraints as the cluster grew larger.
To address this performance concern, KubeArmor now filters watched nodes and pods server-side, reducing overhead significantly in large clusters. Instead of each KubeArmor DaemonSet pod listing and watching every node and pod in the cluster, KubeArmor now specifies the nodes and pods of interest for each DaemonSet. This optimization enhances the overall performance and scalability of KubeArmor in large-scale Kubernetes deployments, ensuring efficient resource utilization and enabling smoother operations in resource-constrained environments.
Special thanks to [dqsully](https://github.com/dqsully) for recognizing and fixing this!

**PRs:** https://github.com/kubearmor/KubeArmor/pull/1676