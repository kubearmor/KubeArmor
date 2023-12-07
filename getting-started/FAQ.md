## FAQs

<details><summary><h4>What platforms are supported by KubeArmor? How can I check whether my deployment will be supported?</h4></summary>

* Please check [Support matrix for KubeArmor](support_matrix.md).
* Use `karmor probe` to check if the platform is supported.
</details>

<details><summary><h4>I am applying a blocking policy but it is not blocking the action. What can I check?</h4></summary>

### Checkout Binary Path
If the path in your process rule is not an absolute path but a symlink, policy enforcement won't work. This is because KubeArmor sees the actual executable path in events received from kernel space and is not aware about symlinks.

Policy enforcement on symbolic links like `/usr/bin/python` doesn't work and one has to specify the path of the actual executable that they link to.

### Checkout Platform Support
Check `karmor probe` output and check whether `Container Security` is false. If it is false, the KubeArmor enforcement is not supported on that platform. You should check the [KubeArmor Support Matrix](support_matrix.md) and if the platform is not listed there then raise a new issue or connect to kubearmor community of slack.

### Checkout Default Posture
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

KubeArmor, apart from been a policy enforcement engine also emits pod/container visibility data. It uses an eBPF-based system monitor which keeps track of process life cycles in containers and even nodes, and converts system metadata to container/node identities. This information can then be used for observability use-cases.

Sample output `karmor logs --json`:
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

The logs are also exportable in [OpenTelemetry format](https://github.com/kubearmor/otel-adapter).

[Detailed KubeArmor events spec](kubearmor-events.md).

</details>

<details><summary><h4>How to visualize KubeArmor visibility logs?</h4></summary>

There are a couple of community maintained dashboards available at [kubearmor/kubearmor-dashboards](https://github.com/kubearmor/kubearmor-dashboards).

If you don't find an existing dashboard particular to your needs, feel free to create an issue. It would be really great if you could also contribute one!
</details>

<details><summary><h4>How to fix `karmor logs` timing out?</h4></summary>

`karmor logs` internally uses Kubernetes' client's port-forward. Port forward is not meant for long running connection and it times out if left idle. Checkout this [StackOverflow answer](https://stackoverflow.com/questions/47484312/kubectl-port-forwarding-timeout-issue) for more info.

If you want to stream logs reliably there are a couple of solutions you can try:
1. Modiy the `kubearmor` service in `kubearmor` namespace and change the service type to `NodePort`. Then run karmor with:
```bash
karmor logs --gRPC=<address of the kubearmor node-port service>
```
This will create a direct, more reliable connection with the service, without any internal port-forward.

2. If you want to stream logs to external tools (fluentd/splunk/ELK etc) checkout [Streaming KubeArmor events](https://github.com/kubearmor/kubearmor-relay-server#streaming-kubearmor-events-to-external-siem-tools).

The community has created adapters and dashboards for some of these tools which can be used out of the box or as reference for creating new adapters. Checkout the previous question for more information.

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

  UEK R7 can be installed on OL 8.6 by following the easy-to-follow instructions provided here in this [Oracle Blog Post](https://blogs.oracle.com/post/uek-7-oracle-linux-8).


> Note: After upgrading to the UEK R7 you may required to enable BPF-LSM if it's not enabled by default.

</details>

<details>
  <summary><h4>Checking and Enabling support for BPF-LSM</h4></summary>


### Checking if BPF-LSM is supported in the Kernel

We check for BPF LSM Support in Kernel Config

```sh
cat /boot/config-$(uname -r) | grep -e "BPF" -e "BTF"
```

Following flags need to exist and set to `y`
```ini
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
```

**Note**: These config could be in other places too like `/boot/config`, `/usr/src/linux-headers-$(uname -r)/.config`, `/lib/modules/$(uname -r)/config`, `/proc/config.gz`.

### Checking if BPF-LSM is enabled

- check if bpf is enabled by verifying if it is in the active lsms.

  ```sh
  $ cat /sys/kernel/security/lsm
  capability,yama,selinux,bpf
  ```
  as we can see here `bpf` is in active lsms

### Enabling BPF-LSM manually using boot configs

- Open the `/etc/default/grub` file in privileged mode.

  ```sh
  sudo vi /etc/default/grub
  ```

    
- Append the following to the `GRUB_CMDLINE_LINUX` variable and save.

  ```
  GRUB_CMDLINE_LINUX="lsm=lockdown,capability,yama,apparmor,bpf"
  ```

- Update grub config:
  ```sh
  # On Debian like systems
  sudo update-grub
  ```
  OR
  ```sh
  # On RHEL like systems
  sudo grub2-mkconfig -o /boot/grub2.cfg
  ```

- Reboot into your kernel.
   ```sh
   sudo reboot
   ```
</details>

<details><summary><h4>ICMP block/audit does not work with AppArmor as the enforcer</h4></summary>
There is some problem with AppArmor due to which ICMP rules don't work as expected.

The KubeArmor team has brought this to the attention of the [AppArmor community](https://stackoverflow.com/questions/76768503/apparmor-deny-icmp-issue) on StackOverflow and await their response.

In the same environment we've found that ICMP rules with BPFLSM work as expected.

For more such differences checkout [Enforce Feature Parity Wiki](https://github.com/kubearmor/KubeArmor/wiki/Enforcer-Feature-Parity).
</details>

<details><summary><h4>How to enable `KubeArmorHostPolicy` for k8s cluster?</h4></summary>
By default the host policies and visibility is disabled for k8s hosts.

If you use following command, `kubectl logs -n kubearmor <KUBEARMOR-POD> | grep "Started to protect"`<br>
you will see, `2023-08-21 12:58:34.641665      INFO    Started to protect containers.`<br>
This indicates that only container/pod protection is enabled.<br>
If you have hostpolicy enabled you should see something like this, `2023-08-22 18:07:43.335232      INFO    Started to protect a host and containers`<br>

One can enable the host policy by patching the daemonset (`kubectl edit daemonsets.apps -n kubearmor kubearmor`):
```diff
...
  template:
    metadata:
      annotations:
        container.apparmor.security.beta.kubernetes.io/kubearmor: unconfined
      creationTimestamp: null
      labels:
        kubearmor-app: kubearmor
    spec:
      containers:
      - args:
        - -gRPC=32767
+       - -enableKubeArmorHostPolicy
+       - -hostVisibility=process,file,network,capabilities
        env:
        - name: KUBEARMOR_NODENAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
...
```

This will enable the `KubeArmorHostPolicy` and host based visibility for the k8s worker nodes.

</details>

<details><summary><h4>Using KubeArmor with Kind clusters</h4></summary>

KubeArmor works out of the box with Kind clusters supporting BPF-LSM. However, with AppArmor only mode, Kind cluster needs additional provisional steps. You can check if BPF-LSM is supported/enabled on your host (on which the kind cluster is to be deployed) by using following:
```
cat /sys/kernel/security/lsm
```
* If it has `bpf` in the list, then everything should work out of the box
* If it has `apparmor` in the list, then follow the steps mentioned in this FAQ.

## 1. Create Kind cluster
```sh
cat <<EOF | kind create cluster --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- extraMounts:
  - hostPath: /sys/kernel/security
    containerPath: /sys/kernel/security
EOF
```

## 2. Exec into kind node & install apparmor util
```sh
docker exec -it kind-control-plane bash -c "apt update && apt install apparmor-utils -y && systemctl restart containerd"
```

The above command will install the AppArmor utilities in the kind-control-plane, we can also use this command to install these in minikube as well as in all the other docker based Kubernetes environments.

After this, exit out of the node shell and follow the [getting-started guide](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md).

It might be possible that apart from the dockerized kubenetes environment AppArmor might not be available on the master node itself in the Kubernetes cluster. To check for the same you can run the below command to check for the AppArmor support in kernel config:

```
cat /boot/config-$(uname -r) | grep -e "APPARMOR"
```

Following flags need to exist and set to `y`
```ini
CONFIG_SECURITY_APPARMOR=y
```

Run the command to install apparmor:

```
apt update && apt install apparmor-utils -y
```

You need to restart your CRI in-order to make APPARMOR available as a kernel config security.

If not then we need to install AppArmor utils on the master node itself.

If the `kubearmor-relay` pod goes into CrashLoopBackOff, apply the following patch:
```sh
kubectl patch deploy -n $(kubectl get deploy -l kubearmor-app=kubearmor-relay -A -o custom-columns=:'{.metadata.namespace}',:'{.metadata.name}') --type=json -p='[{"op": "add", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1kubearmor-relay-server", "value": "unconfined"}]'
```

</details>

<details>
<summary><h4>Debug KubeArmor installation issue</h4></summary>
In certain scenarios, the expected behavior of KubeArmor might not be observed. One way to investigate this is by using the KubeArmor Command Line Interface (CLI) utility, commonly referred to as [karmor cli](https://github.com/kubearmor/kubearmor-client). 

To check the status and configuration of KubeArmor, you can use the following command:

```
karmor probe
```

```
pc:~$ karmor probe

Found KubeArmor running in Kubernetes

Daemonset :

kubearmor Desired: 1 Ready: 1 Available: 1 Deployments :

kubearmor-controller        Desired: 1   Ready: 1   Available: 1 
kubearmor-operator          Desired: 1   Ready: 1   Available: 1 
kubearmor-relay             Desired: 1   Ready: 1   Available: 1

Containers :

kubearmor -apparmor-containerd-98c2c-z772n     Running: 1    Image Version: kubearmor/kubearmor:stable 
kubearmor-controller -6b5d689967-4wxnh         Running: 2    Image Version: gcr.io/kubebuilder/kube-rbac-proxy:v0.12. 
kubearmor -operator -6fb47dd855-6tk5r          Running: 1    Image Version: kubearmor/kubearmor-operator: latest
kubearmor -relay-6966976dbb-hq96h              Running: 1    Image Version: kubearmor/kubearmor-relay-server

Node 1 :

OS Image:                    Debian GNU/Linux 11 (bullseye)

Kernel Version:              6.2.0-36-generic

Kubelet Version:             v1.27.3

Container Runtime:           containerd://1.7.1

Active LSM:

Host Security:               false

Container Security:          false

Container Default Posture:   audit(File)   audit(Capabilities)    audit (Network) 
Host Default Posture:        audit(File)   audit(Capabilities)   audit (Network) 
Host Visibility:             none

Armored Up pods :

------------------------------------------------------------

| NAMESPACE | DEFAULT POSTURE | VISIBILITY | NAME | POLICY |
```

When executing this command, check the output for the value of **ActiveLSM** field, if it is not assigned any value, it means that no active LSM is available for KubeArmor to enforce policies. Under normal circumstances, this value should be assigned a specific Linux Security Module (LSM) that KubeArmor uses to enforce security policies. Additionally, ensure that the **Container Security** field is set to true.

However, there are situations where ActiveLSM might not be assigned any value. This situation indicates that Kubearmor is unable to identify the appropriate LSM in a environment, which is commonly used in Kubernetes setups.

To address this issue, KubeArmor provides a solution involving the use of BPF-LSM. BPF (Berkeley Packet Filter) is a technology that allows efficient packet filtering in the Linux kernel. Enabling support for BPF LSM ensures that KubeArmor can apply and enforce policies as expected in Dockerized environments associated with Kubernetes. Please note that BPFLSM is only available on kernel versions above 5.8 or on RHEL distros > 8.5.

So we need to enable [bpf-lsm](FAQ.md#checking-and-enabling-support-for-bpf-lsm) for Kubearmor to apply and enforce policies as expected.

You can also enable AppArmor if you want to use it as a security module to enforce KubeArmor policies, please refer [here](FAQ.md#using-kubearmor-with-kind-clusters). There is a chance that neither AppArmor nor BPF-LSM is enabled on some nodes. 

**We can apply the following manifest which automatically detects and installs BPFLSM/AppArmor whichever is needed in kubernetes worker nodes.**

```
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/deployments/controller/updaterscript.yaml
```

**Warning:** After running the above script the nodes will restart.
</details>
