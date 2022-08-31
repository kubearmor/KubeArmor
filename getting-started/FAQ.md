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
  * All the OS distributions do not support the LSMs consistently. For e.g, [GKE COS](https://cloud.google.com/container-optimized-os/) supports AppArmor while [Bottlerocket](https://aws.amazon.com/bottlerocket/) supports SELinux and BPF-LSM.  
  * The Pod Security Context expect the security profile to be specified in its native language, for instance, AppArmor profile for AppArmor. SELinux profile if SELinux is to be used. The profile language is extremely complex and this complexity could backfire i.e, it could lead to security holes.  
  * Security Profile updates are manual and difficult: When an app is updated, the security posture might change and it becomes difficult to manually update the native rules.  
  * No alerting of LSM violation on managed cloud platforms: By default LSMs send logs to kernel auditd, which is not available on most managed cloud platforms.  

 KubeArmor solves all the above mentioned problems.
  * It maps YAML rules to LSMs (apparmor, bpf-lsm) rules so prior knowledge of different security context (native AppArmor, SELinux) is not required.  
  * It's easy to deploy: KubeArmor is deployed as a daemonset. Even when the application is updated, the enforcement rules are automatically applied.  
  * Consistent Alerting: KubeArmor has no dependency on kernel auditd. It handles kernel events and maps k8s metadata using ebpf.  
  * KubeArmor also runs in systemd mode so can directly run and protect Virtual Machines or Bare-metal machines too.  
  * Pod Security Context cannot leverage BPF-LSM at all today. BPF-LSM provides more programmatic control over the policy rules.  
  * Pod Security Context do not manage abstractions. As an example, you might have two nodes with Ubuntu, two nodes with Bottlerocket. Ubuntu, by default has AppArmor and Bottlerocket has BPF-LSM and SELinux. KubeArmor internally picks the right primitives to use for enforcement and the user do not have to bother explicitly stating what to use.

</blockquote>
</details>

<details><summary><h5>What are the different approaches to runtime security? How is KubeArmor different?</h5></summary>   
<blockquote>

Most of the available runtime security solutions utilizes post-exploit mitigation techniques for runtime enforcement. It means that a suspicious process is killed in response to an alert indicating malicious intent. But this approach is flawed because:  
  * Attacker already has access to sensitive data  
  * Attacker can disable the defenses before the mitigation can kick in  

KubeArmor avoids these loopholes by using inline mitigation using LSMs. With LSMs the controls are applied even before the process is spawned thus reducing the attack surface in the first place.

</blockquote>
</details>

<details><summary><h5>What is visibility that I hear of in KubeArmor and how to get visibility information?</h5></summary>  
<blockquote>

KubeArmor, apart from been a policy enforcement engine also emits pod/container visibility data. It uses an eBPF-based system monitor which keeps track of process life cycles in containers and even nodes, and converts system metadata to container/node identities. This information can then be used for observability use-cases. Further, this observability information could in turn be used for generating KubeArmor security policies using <a href = "https://github.com/accuknox/discovery-engine"> Discovery Engine </a>  
To get observability data, one can use KubeArmor cli tool <a href = "https://github.com/kubearmor/kubearmor-client"> karmor  </a>  
Sample output `karmor log --json`:
```json
{
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

  You will need to have <a href = "https://github.com/kubearmor/kubearmor-client"> karmor cli utility </a> installed to manage KubeArmor.  
  Following command can be used to to get pod specific events:  
  `karmor log --pod <pod_name>`  
  `karmor log` has following filter to provide more granularity:   
  ```
  --container - Specify container name for container specific logs
  --logFilter <system|policy|all> - Filter to either receive system logs or alerts on policy violation
  --logType <ContainerLog|HostLog> - Source of logs - ContainerLog: logs from containers or HostLog: logs from the host
  --namespace - Specify the namespace for the running pods
  --operation <Process|File|Network> - Type of logs based on process, file or network

  ```
</blockquote>
</details>

<details><summary><h5>How is KubeArmor different from admission controllers?</h5></summary>   
<blockquote>

  Kubernetes admission controllers are set of extensions that acts as a gatekeeper and help govern and control Kubernetes clusters. They intercept requests to the Kubernetes API server prior to the persistence of the object into etcd.  
  They can manage deployments requesting too many resources, enforce pod security policies, prevent vulnerable images from being deployed and check if the pod is running in privileged mode.  
  But all these checks are done before the pods are started. Admission controllers doesn't guarantee any protection once the vulnerability is inside the cluster.  
  KuberArmor protects the pods from within. It runs as a daemonset and restricts the behavior of containers at the system level. KubeArmor allows one to define security policies for the assets/resources (such as files, processes, volumes etc) within the pod/container, select those based on K8s metadata and simply apply these security policies at runtime.  
  It also detects any policy violations and generates audit logs with container identities.  
  Apart from containers, KuberArmor also allows protecting the Host itself.
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
**Allow**: A whitelist policy or a policy defined with `Allow` action allows only the operations defined in the policy, rest everything is blocked. Specifying only the required operations and blocking everything else provide us with a least-permissive policy.  
**Block**: In Blacklisted policy, or policy defined with `Block` action blocks all the operations defined in the policy.  
**Audit**: An applied `Audit` policy doesn't block any action but instead provides alerts on policy violation. This type of policy can be used for "dry-run" before safely applying a security policy in production.  

If Block policy is used and there are no supported enforcement mechanism on the platform then the policy enforcement wouldn't be observed. But we will still be able to see the observability data for the applied Block policy, which can help us in identifying any suspicious activity.
</blockquote>
</details>
