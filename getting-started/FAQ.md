## FAQs

### General Queries

---

<details><summary><h5>What deployments (GKE, EKS, Tanzu, OpenShift) are supported by KubeArmor? How can I check whether my deployment will be supported?</h5></summary>
<blockquote>
Please checkout <a href= "https://github.com/kubearmor/KubeArmor/blob/main/getting-started/support_matrix.md"> Support matrix for KubeArmor </a>
</blockquote>
</details>

<details><summary><h5>How is KubeArmor different from PodSecurityPolicy/PodSecurityContext?</h5></summary>
<blockquote>

 Native k8s supports specifying a security context for the pod or container. It requires one to specify native AppArmor, SELinux, seccomp policies. But there are a few problems with this approach:  
  * All the operating systems doesn't supports the LSMs consistently  
  * It requires knowledge of all of these security context  
  * Security Profile updates are manual and difficult: When an app is updated, the security posture might change and it becomes difficult to manually update the native rules.  
  * No alerting of LSM violation on managed cloud platforms: By default LSMs send logs to kernel auditd, which is not available on most managed cloud platforms.  

 KubeArmor solves all the above mentioned problems.
  * It maps YAML rules to LSMs (apparmor, bpf-lsm) rules so prior knowledge of different security context is not required.  
  * It's easy to deploy: KubeArmor is deployed as a daemonset. Even when the application is updated, the enforcement rules are automatically applied.  
  * Consistent Alerting: KubeArmor has no dependency on kernel auditd. It handles kernel events and maps k8s metadata using ebpf.  
  * KubeArmor also runs in systemd mode so can directly run and protect Virtual Machines or Bare-metal machines too.  
</blockquote>
</details>

<details><summary><h5>What are the different approaches to runtime security? How is KubeArmor different?</h5></summary>   
<blockquote>

Most of the available runtime security solutions utilizes post-exploit mitigation techniques for runtime enforcement. It means that a suspicious process is killed in response to an alert indicating malicious intent. But this approach is flawed because:  
  * Attacker already has access to sensitive data  
  * Attacker can disable the defenses before the mitigation can kick in  

KubeArmor avoids these loopholes by using inline mitigation using LSMs. With LSMs the controls are applied even before the process is spawned thus reduces the attack surface in the first place.

</blockquote>
</details>

<details><summary><h5>What is visibility that I hear of in KubeArmor and how to get visibility information?</h5></summary>  
<blockquote>

KubeArmor, apart from been a policy enforcement engine also emits pod/container visibility data. It uses an eBPF-based system monitor which keeps track of process life cycles in containers and even nodes, and converts system metadata to container/node identities. This information can then be used for observability use-cases. Further, this observability information could in turn be used for generating KubeArmor security policies using <a href = "https://github.com/accuknox/discovery-engine"> Discovery Engine </a>
To get observability data, one can use KubeArmor cli tool known as karmor.  
Sample output `karmor log --json`:
```{
  "Timestamp": 1639803960,
  "UpdatedTime": "2021-12-18T05:06:00.077564Z",
  "ClusterName": "Default",
  "HostName": "pandora",
  "HostPID": 3390423,
  "PPID": 168556,
  "PID": 3390423,
  "UID": 1000,
  "PolicyName": "hsp-kubearmor-dev-proc-path-block",
  "Severity": "1",
  "Type": "MatchedHostPolicy",
  "Source": "zsh",
  "Operation": "Process",
  "Resource": "/usr/bin/sleep",
  "Data": "syscall=SYS_EXECVE",
  "Action": "Block",
  "Result": "Permission denied"
}
```
Here the log implies that the process /usr/bin/sleep execution by 'zsh' was denied on the Host using a blacklisted host policy.

</blockquote>
</details>

<details><summary><h5>How to get process events in the context of a specific pods?</h5></summary>  
<blockquote>
</blockquote>
</details>

<details><summary><h5>How is KubeArmor different from admission controllers?</h5></summary>   
<blockquote>

  Kubernetes admission controllers are set of extensions that help govern and control Kubernetes clusters. They intercepts requests to the Kubernetes API server prior to the persistence of the object into etcd.
  K8s recommends enabling several built-in admission controllers by default to secure the running containers.
  One of the controller is PodSecurity admission plugin, which allows specifying native LSMs policies. But it has it's own limitations:
   * It's very difficult to write native LSMs policies
   * Not all Operating systems supports LSMs consistently
   * Security Profile updates are manual and difficult
</blockquote>
</details>

<details><summary><h5>What is the difference between KubeArmorHostPolicy and KubeArmorPolicy?</h5></summary>
<blockquote>
 KubeArmor protects both the host and the workloads running on it.  

 <a href = "https://github.com/kubearmor/KubeArmor/blob/main/.gitbook/assets/kubearmorpolicy-spec-diagram.pdf">KubeArmorPolicy</a> is the policy specification applied in context of Pods/Containers and <a href = "https://github.com/kubearmor/KubeArmor/blob/main/.gitbook/assets/kubearmorhostpolicy-spec-diagram.pdf"> KubeArmorHostPolicy</a> is for Nodes/VMs.  

<a href ="https://docs.kubearmor.com/kubearmor/getting-started/security_policy_specification">Security Policy Specification for Containers</a>   
<a href = "https://docs.kubearmor.com/kubearmor/getting-started/host_security_policy_specification">Security Policy Specification for Nodes/VMs</a>
</blockquote>
</details>

<details><summary><h5>Where can I find examples of realistic policies for real workloads?</h5></summary>   
<blockquote>
It can be found here in
<a href = "https://github.com/kubearmor/policy-templates"> policy-templates</a>.
</blockquote>
</details>

<details><summary><h5>What are the Policy Actions supported by KubeArmor? What happens if Block policy is used and enforcement is not supported on the platform?</summary>
<blockquote>

KubeArmor defines 3 policy actions: Allow, Block and Audit.
Allow: A whitelist policy or a policy defined with `Allow` action allows only the operations defined in the policy, rest everything is blocked. Specifying only the required operations and blocking everything else provide us with a least-permissive policy.
Block: In Blacklisted policy, or policy defined with `Block` action blocks all the operations defined in the policy.
Audit: An applied `Audit` policy doesn't block any action but instead provides alerts on policy violation. This type of policy can be used for "dry-run" before safely applying a security policy in production.  

If Block policy is used and there are no supported enforcement mechanism on the platform then the policy enforcement wouldn't be observed. But we will still be able to see the observability data for the applied Block policy, which can help us in identifying any suspicious activity.
</blockquote>
</details>
