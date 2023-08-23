# KubeArmor Events

## Supported formats

1. Native Json format (this document)
1. [KubeArmor Open Telemetry format](https://github.com/kubearmor/otel-adapter/blob/main/example/tutorials/tutorial.md)
1. KubeArmor CEF Format (coming soon...)

## Container Telemetry

### Container Telemetry Fields format

| Log field              | Description                                                               | Example                                                                                                       |
|------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| ClusterName            | gives information about the cluster for which the log was generated       | default                                                                                                       |
| Operation              | gives details about what type of operation happened in the pod            | File/Process/ Network                                                                                         |
| ContainerID            | information about the container ID from where log was generated           | 7aca8d52d35ab7872df6a454ca32339386be                                                                          |
| ContainerImage         | shows the image that was used to spin up the container                    | docker.io/accuknox/knoxautopolicy:v0.9@sha256:bb83b5c6d41e0d0aa3b5d6621188c284ea                              |
| ContainerName          | specifies the Container name where the log got generated                  | discovery-engine                                                                                              |
| Data                   | shows the system call that was invoked for this operation                 | syscall=SYS_OPENAT fd=-100 flags=O_RDWR\|O_CREAT\|O_NOFOLLOW\|O_CLOEXEC                                       |
| HostName               | shows the node name where the log got generated                           | aks-agentpool-16128849-vmss000001                                                                             |
| HostPID                | gives the host Process ID                                                 | 967872                                                                                                        |
| HostPPID               | list the details of host Parent Process ID                                | 967496                                                                                                        |
| Labels                 | shows the pod label from where log generated                              | app=discovery-engine                                                                                          |
| Message                | gives the message specified in the policy                                 | Alert! Execution of package management process inside container is denied                                     |
| NamespaceName          | lists the namespace where pod is running                                  | accuknox-agents                                                                                               |
| PID                    | lists the process ID running in container                                 | 1                                                                                                             |
| PPID                   | lists the Parent process ID running in container                          | 967496                                                                                                        |
| ParentProcessName      | gives the parent process name from where the operation happend            | /usr/bin/containerd-shim-runc-v2                                                                              |
| PodName                | lists the pod name where the log got generated                            | mysql-76ddc6ddc4-h47hv                                                                                        |
| ProcessName            | specifies the operation that happened inside the pod for this log         | /knoxAutoPolicy                                                                                               |
| Resource               | lists the resources that was requested                                    | //accuknox-obs.db                                                                                             |
| Result                 | shows whether the event was allowed or denied                             | Passed                                                                                                        |
| Source                 | lists the source from where the operation request came                    | /knoxAutoPolicy                                                                                               |
| Type                   | specifies it as container log                                             | ContainerLog                                                                                                  |

<details><summary><h4>Process Log</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000000",
  "NamespaceName": "default",
  "PodName": "vault-0",
  "Labels": "app.kubernetes.io/instance=vault,app.kubernetes.io/name=vault,component=server,helm.sh/chart=vault-0.24.1,statefulset.kubernetes.io/pod-name=vault-0",
  "ContainerID": "775fb27125ee8d9e2f34d6731fbf3bf677a1038f79fe8134856337612007d9ae",
  "ContainerName": "vault",
  "ContainerImage": "docker.io/hashicorp/vault:1.13.1@sha256:b888abc3fc0529550d4a6c87884419e86b8cb736fe556e3e717a6bc50888b3b8",
  "ParentProcessName": "/usr/bin/runc",
  "ProcessName": "/bin/sh",
  "HostPPID": 2514065,
  "HostPID": 2514068,
  "PPID": 2514065,
  "PID": 3552620,
  "UID": 100,
  "Type": "ContainerLog",
  "Source": "/usr/bin/runc",
  "Operation": "Process",
  "Resource": "/bin/sh -ec vault status -tls-skip-verify",
  "Data": "syscall=SYS_EXECVE",
  "Result": "Passed"
}
```
</details>

<details><summary><h4>File Log</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000000",
  "NamespaceName": "accuknox-agents",
  "PodName": "discovery-engine-6f5c4df7b4-q8zbc",
  "Labels": "app=discovery-engine",
  "ContainerID": "7aca8d52d35ab7872df6a454ca32339386be755d9ed6bd6bf7b37ec6aaf277e4",
  "ContainerName": "discovery-engine",
  "ContainerImage": "docker.io/accuknox/knoxautopolicy:v0.9@sha256:bb83b5c6d41e0d0aa3b5d6621188c284ea99741c3692e34b0f089b0e74745413",
  "ParentProcessName": "/usr/bin/containerd-shim-runc-v2",
  "ProcessName": "/knoxAutoPolicy",
  "HostPPID": 967496,
  "HostPID": 967872,
  "PPID": 967496,
  "PID": 1,
  "Type": "ContainerLog",
  "Source": "/knoxAutoPolicy",
  "Operation": "File",
  "Resource": "/var/run/secrets/kubernetes.io/serviceaccount/token",
  "Data": "syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_CLOEXEC",
  "Result": "Passed"
}
```
</details>

<details><summary><h4>Network Log</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000001",
  "NamespaceName": "accuknox-agents",
  "PodName": "policy-enforcement-agent-7946b64dfb-f4lgv",
  "Labels": "app=policy-enforcement-agent",
  "ContainerID": "b597629c9b59304c779c51839e9a590fa96871bdfdf55bfec73b26c9fb7647d7",
  "ContainerName": "policy-enforcement-agent",
  "ContainerImage": "public.ecr.aws/k9v9d5v2/policy-enforcement-agent:v0.1.0@sha256:005c1fde3ff8a667f3ac7540c5c011c752a7e3aaa2c89aa335703289ed8d80f8",
  "ParentProcessName": "/usr/bin/containerd-shim-runc-v2",
  "ProcessName": "/home/pea/main",
  "HostPPID": 1394403,
  "HostPID": 1394554,
  "PPID": 1394403,
  "PID": 1,
  "Type": "ContainerLog",
  "Source": "./main",
  "Operation": "Network",
  "Resource": "sa_family=AF_INET sin_port=53 sin_addr=10.0.0.10",
  "Data": "syscall=SYS_CONNECT fd=10",
  "Result": "Passed"
}
```
</details>

## Container Alerts

Container alerts are generated when there is a policy violation or audit event that is raised due to a policy action. For example, a policy might block execution of a process. When the execution is blocked by KubeArmor enforcer, KubeArmor generates an alert event implying policy action. In the case of an Audit action, the KubeArmor will only generate an alert without actually blocking the action.

The primary difference in the container alerts events vs the telemetry events (showcased above) is that the alert events contains certain additional fields such as policy name because of which the alert was generated and other metadata such as "Tags", "Message", "Severity" associated with the policy rule.

### Container Alerts Fields format

| Alert Field            | Description                                                                          | Example                                                                                              |
|------------------------|--------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| Action                 | specifies the action of the policy it has matched.                                   | Audit/Block                                                                                          |
| ClusterName            | gives information about the cluster for which the alert was generated                | aks-test-cluster                                                                                     |
| Operation              | gives details about what type of operation happened in the pod                       | File/Process/Network                                                                                 |
| ContainerID            | information about the container ID where the policy violation or alert got generated | e10d5edb62ac2daa4eb9a2146e2f2cfa87b6a5f30bd3a                                                        |
| ContainerImage         | shows the image that was used to spin up the container                               | docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f                                |
| ContainerName          | specifies the Container name where the alert got generated                           | mysql                                                                                                |
| Data                   | shows the system call that was invoked for this operation                            | syscall=SYS_EXECVE                                                                                   |
| Enforcer               | it specifies the name of the LSM that has enforced the policy                        | AppArmor/BPFLSM                                                                                      |
| HostName               | shows the node name where the alert got generated                                    | aks-agentpool-16128849-vmss000001                                                                    |
| HostPID                | gives the host Process ID                                                            | 3647533                                                                                              |
| HostPPID               | list the details of host Parent Process ID                                           | 3642706                                                                                              |
| Labels                 | shows the pod label from where alert generated                                       | app=mysql                                                                                            |
| Message                | gives the message specified in the policy                                            | Alert! Execution of package management process inside container is denied                            |
| NamespaceName          | lists the namespace where pod is running                                             | wordpress-mysql                                                                                      |
| PID                    | lists the process ID running in container                                            | 266                                                                                                  |
| PPID                   | lists the Parent process ID running in container                                     | 251                                                                                                  |
| ParentProcessName      | gives the parent process name from where the operation happend                       | /bin/bash                                                                                            |
| PodName                | lists the pod name where the alert got generated                                     | mysql-76ddc6ddc4-h47hv                                                                               |
| PolicyName             | gives the policy that was matched for this alert generation                          | harden-mysql-pkg-mngr-exec                                                                           |
| ProcessName            | specifies the operation that happened inside the pod for this alert                  | /usr/bin/apt                                                                                         |
| Resource               | lists the resources that was requested                                               | /usr/bin/apt                                                                                         |
| Result                 | shows whether the event was allowed or denied                                        | Permission denied                                                                                    |
| Severity               | gives the severity level of the operation                                            | 5                                                                                                    |
| Source                 | lists the source from where the operation request came                               | /bin/bash                                                                                            |
| Tags                   | specifies the list of benchmarks this policy satisfies                               | NIST,NIST_800-53_CM-7(4),SI-4,process,NIST_800-53_SI-4                                               |
| Timestamp              | gives the details of the time this event tried to happen                             | 1687868507                                                                                           |
| Type                   | shows whether policy matched or default posture alert                                | MatchedPolicy                                                                                        |
| UpdatedTime            | gives the time of this alert                                                         | 2023-06-27T12:21:47.932526                                                                           |
| cluster_id             | specifies the cluster id where the alert was generated                               | 596                                                                                                  |
| component_name         | gives the component which generated this log/alert                                   | kubearmor                                                                                            |
| tenant_id              | specifies the tenant id where this cluster is onboarded in AccuKnox SaaS             | 11                                                                                                   |

<details><summary><h4>Process Alert</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000001",
  "NamespaceName": "wordpress-mysql",
  "PodName": "wordpress-787f45786f-2q9wf",
  "Labels": "app=wordpress",
  "ContainerID": "72de193fc8d849cd052affae5a53a27111bcefb75385635dcb374acdf31a5548",
  "ContainerName": "wordpress",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "HostPPID": 495804,
  "HostPID": 495877,
  "PPID": 309835,
  "PID": 309841,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/usr/bin/apt",
  "PolicyName": "harden-wordpress-pkg-mngr-exec",
  "Severity": "5",
  "Tags": "NIST,NIST_800-53_CM-7(4),SI-4,process,NIST_800-53_SI-4",
  "ATags": [
    "NIST",
    "NIST_800-53_CM-7(4)",
    "SI-4",
    "process",
    "NIST_800-53_SI-4"
  ],
  "Message": "Alert! Execution of package management process inside container is denied",
  "Type": "MatchedPolicy",
  "Source": "/bin/bash",
  "Operation": "Process",
  "Resource": "/usr/bin/apt",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "Action": "Block",
  "Result": "Permission denied"
}
```
</details>
<details><summary><h4>File Alert</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000001",
  "NamespaceName": "wordpress-mysql",
  "PodName": "wordpress-787f45786f-2q9wf",
  "Labels": "app=wordpress",
  "ContainerID": "72de193fc8d849cd052affae5a53a27111bcefb75385635dcb374acdf31a5548",
  "ContainerName": "wordpress",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "HostPPID": 495804,
  "HostPID": 496390,
  "PPID": 309835,
  "PID": 309842,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/bin/rm",
  "PolicyName": "harden-wordpress-file-integrity-monitoring",
  "Severity": "1",
  "Tags": "NIST,NIST_800-53_AU-2,NIST_800-53_SI-4,MITRE,MITRE_T1036_masquerading,MITRE_T1565_data_manipulation",
  "ATags": [
    "NIST",
    "NIST_800-53_AU-2",
    "NIST_800-53_SI-4",
    "MITRE",
    "MITRE_T1036_masquerading",
    "MITRE_T1565_data_manipulation"
  ],
  "Message": "Detected and prevented compromise to File integrity",
  "Type": "MatchedPolicy",
  "Source": "/bin/rm /sbin/raw",
  "Operation": "File",
  "Resource": "/sbin/raw",
  "Data": "syscall=SYS_UNLINKAT flags=",
  "Enforcer": "AppArmor",
  "Action": "Block",
  "Result": "Permission denied"
}
```
</details>
<details><summary><h4>Network Alert</h4></summary>

```json
{
  "ClusterName": "default",
  "HostName": "aks-agentpool-16128849-vmss000000",
  "NamespaceName": "default",
  "PodName": "vault-0",
  "Labels": "app.kubernetes.io/instance=vault,app.kubernetes.io/name=vault,component=server,helm.sh/chart=vault-0.24.1,statefulset.kubernetes.io/pod-name=vault-0",
  "ContainerID": "775fb27125ee8d9e2f34d6731fbf3bf677a1038f79fe8134856337612007d9ae",
  "ContainerName": "vault",
  "ContainerImage": "docker.io/hashicorp/vault:1.13.1@sha256:b888abc3fc0529550d4a6c87884419e86b8cb736fe556e3e717a6bc50888b3b8",
  "HostPPID": 2203523,
  "HostPID": 2565259,
  "PPID": 2203523,
  "PID": 3558570,
  "UID": 100,
  "ParentProcessName": "/usr/bin/containerd-shim-runc-v2",
  "ProcessName": "/bin/vault",
  "PolicyName": "ksp-vault-network",
  "Severity": "8",
  "Type": "MatchedPolicy",
  "Source": "/bin/vault status -tls-skip-verify",
  "Operation": "Network",
  "Resource": "domain=AF_UNIX type=SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
  "Data": "syscall=SYS_SOCKET",
  "Enforcer": "eBPF Monitor",
  "Action": "Audit",
  "Result": "Passed"
}
```
</details>

## Host Alerts

The fields are self-explanatory and have similar meaning as in the context of container based events (explained above).

<details><summary><h4>Process Alert</h4></summary>

```json
{
  "Timestamp": 1692813948,
  "UpdatedTime": "2023-08-23T18:05:48.301798Z",
  "ClusterName": "default",
  "HostName": "gke-my-first-cluster-1-default-pool-9144db50-81gb",
  "HostPPID": 1979,
  "HostPID": 1787227,
  "PPID": 1979,
  "PID": 1787227,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/bin/sleep",
  "PolicyName": "sleep-deny",
  "Severity": "5",
  "Type": "MatchedHostPolicy",
  "Source": "/bin/bash",
  "Operation": "Process",
  "Resource": "/usr/bin/sleep 10",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Permission denied"
}
```
</details>

<details><summary><h4>Blocked SETGID</h4></summary>

Note that KubeArmor also alerts events blocked due to other system policy enforcement. For example, if an SELinux native rule blocks an action, KubeArmor will report those as well as `DefaultPosture` events. Following is an example of such event:

```json
{
  "Timestamp": 1692814089,
  "UpdatedTime": "2023-08-23T18:08:09.522743Z",
  "ClusterName": "default",
  "HostName": "gke-my-first-cluster-1-default-pool-9144db50-81gb",
  "HostPPID": 1791315,
  "HostPID": 1791316,
  "PPID": 1791315,
  "PID": 1791316,
  "UID": 204,
  "ParentProcessName": "/usr/sbin/sshd",
  "ProcessName": "/usr/sbin/sshd",
  "PolicyName": "DefaultPosture",
  "Type": "MatchedHostPolicy",
  "Source": "/usr/sbin/sshd",
  "Operation": "Syscall",
  "Data": "syscall=SYS_SETGID userid=0",
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Operation not permitted"
}
```
</details>

<details><summary><h4>Blocked SETUID</h4></summary>

Note that KubeArmor also alerts events blocked due to other system policy enforcement. For example, if an SELinux native rule blocks an action, KubeArmor will report those as well as `DefaultPosture` events. Following is an example of such event:
```json
{
  "Timestamp": 1692814089,
  "UpdatedTime": "2023-08-23T18:08:09.523964Z",
  "ClusterName": "default",
  "HostName": "gke-my-first-cluster-1-default-pool-9144db50-81gb",
  "HostPPID": 1791315,
  "HostPID": 1791316,
  "PPID": 1791315,
  "PID": 1791316,
  "UID": 204,
  "ParentProcessName": "/usr/sbin/sshd",
  "ProcessName": "/usr/sbin/sshd",
  "PolicyName": "DefaultPosture",
  "Type": "MatchedHostPolicy",
  "Source": "/usr/sbin/sshd",
  "Operation": "Syscall",
  "Data": "syscall=SYS_SETUID userid=0",
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Operation not permitted"
}
```
</details>
