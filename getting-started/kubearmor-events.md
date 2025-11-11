1: # KubeArmor Events
2: 
3: ## Supported formats
4: 
5: 1. Native Json format (this document)
6: 1. [KubeArmor Open Telemetry format](https://github.com/kubearmor/otel-adapter/blob/main/example/tutorials/tutorial.md)
7: 1. KubeArmor CEF Format (coming soon...)
8: 
9: ## Container Telemetry
10: 
11: ### Container Telemetry Fields format
12: 
13: | Log field              | Description                                                               | Example                                                                                                       |
14: |------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
15: | ClusterName            | gives information about the cluster for which the log was generated       | default                                                                                                       |
16: | Operation              | gives details about what type of operation happened in the pod            | File/Process/ Network                                                                                         |
17: | ContainerID            | information about the container ID from where log was generated           | 7aca8d52d35ab7872df6a454ca32339386be                                                                          |
18: | ContainerImage         | shows the image that was used to spin up the container                    | docker.io/accuknox/knoxautopolicy:v0.9@sha256:bb83b5c6d41e0d0aa3b5d6621188c284ea                              |
19: | ContainerName          | specifies the Container name where the log got generated                  | discovery-engine                                                                                              |
20: | Data                   | shows the system call that was invoked for this operation                 | syscall=SYS_OPENAT fd=-100 flags=O_RDWR\|O_CREAT\|O_NOFOLLOW\|O_CLOEXEC                                       |
21: | EventData              | structured key/value context for the event                                | {"syscall":"openat","fd":"-100","flags":"O_RDONLY","devClass":"HID"}                                 |
22: | HostName               | shows the node name where the log got generated                           | aks-agentpool-16128849-vmss000001                                                                             |
23: | HostPID                | gives the host Process ID                                                 | 967872                                                                                                        |
24: | HostPPID               | list the details of host Parent Process ID                                | 967496                                                                                                        |
25: | Labels                 | shows the pod label from where log generated                              | app=discovery-engine                                                                                          |
26: | Message                | gives the message specified in the policy                                 | Alert! Execution of package management process inside container is denied                                     |
27: | NamespaceName          | lists the namespace where pod is running                                  | accuknox-agents                                                                                               |
28: | PID                    | lists the process ID running in container                                 | 1                                                                                                             |
29: | PPID                   | lists the Parent process ID running in container                          | 967496                                                                                                        |
30: | ParentProcessName      | gives the parent process name from where the operation happend            | /usr/bin/containerd-shim-runc-v2                                                                              |
31: | PodName                | lists the pod name where the log got generated                            | mysql-76ddc6ddc4-h47hv                                                                                        |
32: | ProcessName            | specifies the operation that happened inside the pod for this log         | /knoxAutoPolicy                                                                                               |
33: | Resource               | lists the resources that was requested                                    | //accuknox-obs.db                                                                                             |
34: | Result                 | shows whether the event was allowed or denied                             | Passed                                                                                                        |
35: | Source                 | lists the source from where the operation request came                    | /knoxAutoPolicy                                                                                               |
36: | Type                   | specifies it as container log                                             | ContainerLog                                                                                                  |
37: 
38: <details><summary><h4>Process Log</h4></summary>
39: 
40: ```json
41: {
42:   "ClusterName": "default",
43:   "HostName": "aks-agentpool-16128849-vmss000000",
44:   "NamespaceName": "default",
45:   "PodName": "vault-0",
46:   "Labels": "app.kubernetes.io/instance=vault,app.kubernetes.io/name=vault,component=server,helm.sh/chart=vault-0.24.1,statefulset.kubernetes.io/pod-name=vault-0",
47:   "ContainerID": "775fb27125ee8d9e2f34d6731fbf3bf677a1038f79fe8134856337612007d9ae",
48:   "ContainerName": "vault",
49:   "ContainerImage": "docker.io/hashicorp/vault:1.13.1@sha256:b888abc3fc0529550d4a6c87884419e86b8cb736fe556e3e717a6bc50888b3b8",
50:   "ParentProcessName": "/usr/bin/runc",
51:   "ProcessName": "/bin/sh",
52:   "HostPPID": 2514065,
53:   "HostPID": 2514068,
54:   "PPID": 2514065,
55:   "PID": 3552620,
56:   "UID": 100,
57:   "Type": "ContainerLog",
58:   "Source": "/usr/bin/runc",
59:   "Operation": "Process",
60:   "Resource": "/bin/sh -ec vault status -tls-skip-verify",
61:   "Data": "syscall=SYS_EXECVE",
62:   "EventData": {"syscall":"execve","argv":"-ec vault status -tls-skip-verify"},
63:   "Result": "Passed"
64: }
65: ```
66: </details>
67: 
68: <details><summary><h4>File Log</h4></summary>
69: 
70: ```json
71: {
72:   "ClusterName": "default",
73:   "HostName": "aks-agentpool-16128849-vmss000000",
74:   "NamespaceName": "accuknox-agents",
75:   "PodName": "discovery-engine-6f5c4df7b4-q8zbc",
76:   "Labels": "app=discovery-engine",
77:   "ContainerID": "7aca8d52d35ab7872df6a454ca32339386be755d9ed6bd6bf7b37ec6aaf277e4",
78:   "ContainerName": "discovery-engine",
79:   "ContainerImage": "docker.io/accuknox/knoxautopolicy:v0.9@sha256:bb83b5c6d41e0d0aa3b5d6621188c284ea99741c3692e34b0f089b0e74745413",
80:   "ParentProcessName": "/usr/bin/containerd-shim-runc-v2",
81:   "ProcessName": "/knoxAutoPolicy",
82:   "HostPPID": 967496,
83:   "HostPID": 967872,
84:   "PPID": 967496,
85:   "PID": 1,
86:   "Type": "ContainerLog",
87:   "Source": "/knoxAutoPolicy",
88:   "Operation": "File",
89:   "Resource": "/var/run/secrets/kubernetes.io/serviceaccount/token",
90:   "Data": "syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_CLOEXEC",
91:   "EventData": {"syscall":"openat","fd":"-100","flags":"O_RDONLY|O_CLOEXEC"},
92:   "Result": "Passed"
93: }
94: ```
95: </details>
96: 
97: <details><summary><h4>Network Log</h4></summary>
98: 
99: ```json
100: {
101:   "ClusterName": "default",
102:   "HostName": "aks-agentpool-16128849-vmss000001",
103:   "NamespaceName": "accuknox-agents",
104:   "PodName": "policy-enforcement-agent-7946b64dfb-f4lgv",
105:   "Labels": "app=policy-enforcement-agent",
106:   "ContainerID": "b597629c9b59304c779c51839e9a590fa96871bdfdf55bfec73b26c9fb7647d7",
107:   "ContainerName": "policy-enforcement-agent",
108:   "ContainerImage": "public.ecr.aws/k9v9d5v2/policy-enforcement-agent:v0.1.0@sha256:005c1fde3ff8a667f3ac7540c5c011c752a7e3aaa2c89aa335703289ed8d80f8",
109:   "ParentProcessName": "/usr/bin/containerd-shim-runc-v2",
110:   "ProcessName": "/home/pea/main",
111:   "HostPPID": 1394403,
112:   "HostPID": 1394554,
113:   "PPID": 1394403,
114:   "PID": 1,
115:   "Type": "ContainerLog",
116:   "Source": "./main",
117:   "Operation": "Network",
118:   "Resource": "sa_family=AF_INET sin_port=53 sin_addr=10.0.0.10",
119:   "Data": "syscall=SYS_CONNECT fd=10",
120:   "EventData": {"syscall":"connect","fd":"10","sa_family":"AF_INET","port":"53"},
121:   "Result": "Passed"
122: }
123: ```
124: </details>
125: 
126: ## Container Alerts
127: 
128: Container alerts are generated when there is a policy violation or audit event that is raised due to a policy action. For example, a policy might block execution of a process. When the execution is blocked by KubeArmor enforcer, KubeArmor generates an alert event implying policy action. In the case of an Audit action, the KubeArmor will only generate an alert without actually blocking the action.
129: 
130: The primary difference in the container alerts events vs the telemetry events (showcased above) is that the alert events contains certain additional fields such as policy name because of which the alert was generated and other metadata such as \"Tags\", \"Message\", \"Severity\" associated with the policy rule.
131: 
132: ### Container Alerts Fields format
133: 
134: | Alert Field            | Description                                                                          | Example                                                                                              |
135: |------------------------|--------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
136: | Action                 | specifies the action of the policy it has matched.                                   | Audit/Block                                                                                          |
137: | ClusterName            | gives information about the cluster for which the alert was generated                | aks-test-cluster                                                                                     |
138: | Operation              | gives details about what type of operation happened in the pod                       | File/Process/Network                                                                                 |
139: | ContainerID            | information about the container ID where the policy violation or alert got generated | e10d5edb62ac2daa4eb9a2146e2f2cfa87b6a5f30bd3a                                                        |
140: | ContainerImage         | shows the image that was used to spin up the container                               | docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f                                |
141: | ContainerName          | specifies the Container name where the alert got generated                           | mysql                                                                                                |
142: | Data                   | shows the system call that was invoked for this operation                            | syscall=SYS_EXECVE                                                                                   |
143: | EventData              | structured key/value context for the event (e.g., args, hashes, device metadata)     | {"syscall":"execve","argv":"/usr/bin/apt"}                                                       |
144: | Enforcer               | it specifies the name of the LSM that has enforced the policy                        | AppArmor/BPFLSM                                                                                      |
145: | HostName               | shows the node name where the alert got generated                                    | aks-agentpool-16128849-vmss000001                                                                    |
146: | HostPID                | gives the host Process ID                                                            | 3647533                                                                                              |
147: | HostPPID               | list the details of host Parent Process ID                                           | 3642706                                                                                              |
148: | Labels                 | shows the pod label from where alert generated                                       | app=mysql                                                                                            |
149: | Message                | gives the message specified in the policy                                            | Alert! Execution of package management process inside container is denied                            |
150: | NamespaceName          | lists the namespace where pod is running                                             | wordpress-mysql                                                                                      |
151: | PID                    | lists the process ID running in container                                            | 266                                                                                                  |
152: | PPID                   | lists the Parent process ID running in container                                     | 251                                                                                                  |
153: | ParentProcessName      | gives the parent process name from where the operation happend                       | /bin/bash                                                                                            |
154: | PodName                | lists the pod name where the alert got generated                                     | mysql-76ddc6ddc4-h47hv                                                                               |
155: | PolicyName             | gives the policy that was matched for this alert generation                          | harden-mysql-pkg-mngr-exec                                                                           |
156: | ProcessName            | specifies the operation that happened inside the pod for this alert                  | /usr/bin/apt                                                                                         |
157: | Resource               | lists the resources that was requested                                               | /usr/bin/apt                                                                                         |
158: | Result                 | shows whether the event was allowed or denied                                        | Permission denied                                                                                    |
159: | Severity               | gives the severity level of the operation                                            | 5                                                                                                    |
160: | Source                 | lists the source from where the operation request came                               | /bin/bash                                                                                            |
161: | Tags                   | specifies the list of benchmarks this policy satisfies                               | NIST,NIST_800-53_CM-7(4),SI-4,process,NIST_800-53_SI-4                                               |
162: | Timestamp              | gives the details of the time this event tried to happen                             | 1687868507                                                                                           |
163: | Type                   | shows whether policy matched or default posture alert                                | MatchedPolicy                                                                                        |
164: | UpdatedTime            | gives the time of this alert                                                         | 2023-06-27T12:21:47.932526                                                                           |
165: | cluster_id             | specifies the cluster id where the alert was generated                               | 596                                                                                                  |
166: | component_name         | gives the component which generated this log/alert                                   | kubearmor                                                                                            |
167: | tenant_id              | specifies the tenant id where this cluster is onboarded in AccuKnox SaaS             | 11                                                                                                   |

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
