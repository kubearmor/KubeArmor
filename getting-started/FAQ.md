## FAQs

<details><summary><h4>What platforms are supported by KubeArmor? How can I check whether my deployment will be supported?</h4></summary>

* Please check [Support matrix for KubeArmor](default_posture.md).
* Use `karmor probe` to check if the platform is supported.
</details>

<details><summary><h4>I am applying a blocking policy but it is not blocking the action. What can I check?</h4></summary>

Check `karmor probe` output and check whether `Container Security` is false. If it is false, the KubeArmor enforcement is not supported on that platform. You should check the [KubeArmor Support Matrix](support_matrix.ma) and if the platform is not listed there then raise a new issue or connect to kubearmor community of slack.

If you are applying an Allow-based policies and expecting unknown actions to be blocked, please make sure to check the [default security posture](default_posture.md). The default security posture is set to Audit by default since KubeArmor v0.7.
</details>

<details><summary><h4>How is KubeArmor different from PodSecurityPolicy/PodSecurityContext?</h4></summary>

Native k8s supports specifying a security context for the pod or container. It requires one to specify native AppArmor, SELinux, seccomp policies. But there are a few problems with this approach:  
* All the OS distributions do not support the LSMs consistently. For e.g, [GKE COS](https://cloud.google.com/container-optimized-os/) supports AppArmor while [Bottlerocket](https://aws.amazon.com/bottlerocket/) supports SELinux and BPF-LSM.  
* The Pod Security Context expect the security profile to be specified in its native language, for instance, AppArmor profile for AppArmor. SELinux profile if SELinux is to be used. The profile language is extremely complex and this complexity could backfire i.e, it could lead to security holes.  
* Security Profile updates are manual and difficult: When an app is updated, the security posture might change and it becomes difficult to manually update the native rules.  
* No alerting of LSM violation on managed cloud platforms: By default LSMs send logs to kernel auditd, which is not available on most managed cloud platforms.  

KubeArmor solves all the above mentioned problems.
* It maps YAML rules to LSMs (apparmor, bpf-lsm) rules so prior knowledge of different security context (native AppArmor, SELinux) is not required.  
* It's easy to deploy: KubeArmor is deployed as a daemonset. Even when the application is updated, the enforcement rules are automatically applied.  
* Consistent Alerting: KubeArmor handles kernel events and maps k8s metadata using ebpf.  
* KubeArmor also runs in systemd mode so can directly run and protect Virtual Machines or Bare-metal machines too.  
* Pod Security Context cannot leverage BPF-LSM at all today. BPF-LSM provides more programmatic control over the policy rules.  
* Pod Security Context do not manage abstractions. As an example, you might have two nodes with Ubuntu, two nodes with Bottlerocket. Ubuntu, by default has AppArmor and Bottlerocket has BPF-LSM and SELinux. KubeArmor internally picks the right primitives to use for enforcement and the user do not have to bother explicitly stating what to use.
</details>

<details><summary><h4>What is visibility that I hear of in KubeArmor and how to get visibility information?</h4></summary>  

KubeArmor, apart from been a policy enforcement engine also emits pod/container visibility data. It uses an eBPF-based system monitor which keeps track of process life cycles in containers and even nodes, and converts system metadata to container/node identities. This information can then be used for observability use-cases. Further, this observability information could in turn be used for generating KubeArmor security policies using [Discovery Engine](https://github.com/accuknox/discovery-engine). To get observability data, one can use [KubeArmor cli tool aka `karmor`](https://github.com/kubearmor/kubearmor-client).

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
Here the log implies that the process /usr/bin/sleep execution by 'zsh' was denied on the Host using a block based host policy.
</details>

<details><summary><h4>How to get process events in the context of a specific pods?</h4></summary>  

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
</details>

<details><summary><h4>How is KubeArmor different from admission controllers?</h4></summary>   

Kubernetes admission controllers are set of extensions that acts as a gatekeeper and help govern and control Kubernetes clusters. They intercept requests to the Kubernetes API server prior to the persistence of the object into etcd.  

They can manage deployments requesting too many resources, enforce pod security policies, prevent vulnerable images from being deployed and check if the pod is running in privileged mode.  
But all these checks are done before the pods are started. Admission controllers doesn't guarantee any protection once the vulnerability is inside the cluster.  

KuberArmor protects the pods from within. It runs as a daemonset and restricts the behavior of containers at the system level. KubeArmor allows one to define security policies for the assets/resources (such as files, processes, volumes etc) within the pod/container, select those based on K8s metadata and simply apply these security policies at runtime.

It also detects any policy violations and generates audit logs with container identities. Apart from containers, KuberArmor also allows protecting the Host itself.
</details>

<details><summary><h4>What are the Policy Actions supported by KubeArmor?</h4></summary>

KubeArmor defines 3 policy actions: Allow, Block and Audit.  
**Allow**: A whitelist policy or a policy defined with `Allow` action allows only the operations defined in the policy, rest everything is blocked/audited.
**Block**: Policy defined with `Block` action blocks all the operations defined in the policy.  
**Audit**: An applied `Audit` policy doesn't block any action but instead provides alerts on policy violation. This type of policy can be used for "dry-run" before safely applying a security policy in production.  

If Block policy is used and there are no supported enforcement mechanism on the platform then the policy enforcement wouldn't be observed. But we will still be able to see the observability data for the applied Block policy, which can help us in identifying any suspicious activity.
</details>

<details>
  <summary><h4>How to use KubeArmor on Oracle K8s engine?</h4></summary>

KubeArmor supports enforcement on OKE leveraging the BPF-LSM. The default kernel for Oracle Linux 8.6 (OL 8.6) is UEK R6 kernel-uek-5.4.17-2136.307.3 which does not support BPF-LSM.

Unbreakable Enterprise Kernel Release 7 (UEK R7) is based on Linux kernel 5.15 LTS that supports BPF-LSM and it's available for Oracle Linux 8 Update 5 onwards.

### Installing UEK 7 on OL 8.6

  UEK R7 can be installed on OL 8.6 by following the easy-to-follow instructions provided here in this [Oracle Blog Post](https://blogs.oracle.com/scoter/post/uek-7-oracle-linux-8).


> Note: After upgrading to the UEK R7 you may required to enable BPF-LSM if it's not enabled by default.

### Checking if BPF-LSM is enabled

- check if bpf is enabled by verifying if it is in the active lsms.

  ```
  $ cat /sys/kernel/security/lsm
  capability,yama,selinux,bpf
  ```
  as we can see here `bpf` is in active lsms

### Enabling BPF-LSM manually using boot configs

- Open the `/etc/default/grub` file in privileged mode.

  ```
  $ sudo vi /etc/default/grub
  ```

    
- Append the following to the `GRUB_CMDLINE_LINUX` variable and save.

  ```
  GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,apparmor,bpf"
  ```

- Update grub config:
  ```
  $ sudo grub2-mkconfig -o /boot/grub2.cfg
  ```

- Reboot into your kernel.
   ```
   $ sudo reboot
   ```
</details>
