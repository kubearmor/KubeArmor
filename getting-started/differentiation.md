# KubeArmor Differentiation

<img src="../.gitbook/assets/differentiation.png" width="784" class="center" alt="KubeArmor Differentiation">

## Significance of Inline Mitigation

KubeArmor supports prevention of attacks, not just observability and monitoring. More importantly, the prevention is handled inline i.e, for e.g, even before a process is spawned, the rule can deny execution of that process. Most of the other systems typically employ something called as post-attack mitigation that kills the process/pod after the malicious intent is observed, allowing the attacker to execute its code in the target environment. Essentially KubeArmor uses inline mitigation to reduce the attack surface of pod/container/VM. KubeArmor leverages best of breed Linux Security Modules (LSMs) such as AppArmor, BPF-LSM, and SELinux (only for host protection) for inline mitigation. LSMs have several advantages over any other technique:
* KubeArmor does not change anything with the pod/container.
* KubeArmor does not require and change at the host level or at the CRI (Container Runtime Interface) level to enforce blocking rules. KubeArmor deploys as a non-privileged daemonset with certain capabilities that allows it to monitor other pods/containers and host.
* A given cluster can multiple nodes utilizing different LSMs. KubeArmor abstracts away the complexities of the LSMs and provides an easy way for policy enforcement. KubeArmor manages the complexity of the LSMs under-the-hood.

### Post-Attack Mitigation and it flaws

<img src="../.gitbook/assets/post-attack-mitigation.png" width="400" class="center" alt="Post Attack Mitigation">

* Post-exploit Mitigation works by killing the suspicious process in response to an alert indicating malicious intent.
* Attacker is allowed to executes its binary. Attacker could possibly disable the security controls, access logs, etc to circumvent the attack detection.
* By the time, the malicious process is killed, it might have already deleted, encrypted, or transmitted the sensitive contents.
* [Quoting Grsecurity](https://grsecurity.net/tetragone_a_lesson_in_security_fundamentals), “post-exploitation detection/mitigation is at the mercy of an exploit writer putting little to no effort into avoiding tripping these detection mechanisms.”

[Here](https://grsecurity.net/tetragone_a_lesson_in_security_fundamentals) is the reference on why Post-Attack Mitigation is a flawed technique.

## Problems with k8s native Pod Security Context

[Pod Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/) allows one to specify [native apparmor](https://kubernetes.io/docs/tutorials/security/apparmor/) or native selinux policy.

<img src="../.gitbook/assets/pod security context.png" width="512" class="center" alt="Pod Security Context">

This approach has multiple problems:
1. It is often difficult to predict which LSM (AppArmor or SELinux) would be available on the target node.
2. BPF-LSM is not supported by Pod Security Context.
3. It is difficult to manually specify the apparmor or selinux policy. Changing default apparmor or selinux policies might result in more security holes since it is difficult to decipher the implications of the changes and can be counter-productive.

### Problems with multicloud deployment

Different managed cloud providers use different default distributions. Google GKE COS uses AppArmor by default, AWS Bottlerocket uses BPF-LSM and SElinux, and AWS Amazon Linux 2 uses only SElinux by default. Thus it becomes challenging to use pod security context in multi cloud deployments.

<img src="../.gitbook/assets/multi-cloud.png" width="784" class="center" alt="Multi Cloud issues with LSMs">

## Use of BPF-LSM

<img src="../.gitbook/assets/bpf-lsm.png" width="512" class="center" alt="BPF-LSM with KubeArmor">

References:
* [Armoring Cloud Native Workloads with BPF-LSM](https://www.youtube.com/watch?v=uYVaiIX7QC0&ab_channel=CNCF%5BCloudNativeComputingFoundation%5D)
* [Securing Bottlerocket deployments on Amazon EKS with KubeArmor](https://aws.amazon.com/blogs/containers/secure-bottlerocket-deployments-on-amazon-eks-with-kubearmor/)
