#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# apt
bash: /usr/bin/apt: Permission denied
root@mysql-74775b4bf4-65nqf:/# apt-get
bash: /usr/bin/apt-get: Permission denied
```

#### Expected Alert
```
{
  "ATags": [
    "NIST",
    "NIST_800-53_CM-7(4)",
    "SI-4",
    "process",
    "NIST_800-53_SI-4"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HashID": "dd573c234f68b8df005e8cd314809c8b2a23852230d397743e348bf4a03ada3f",
  "HostName": "aditya",
  "HostPID": 21894,
  "HostPPID": 16435,
  "Labels": "app=mysql",
  "Message": "Alert! Execution of package management process inside container is denied",
  "NamespaceName": "wordpress-mysql",
  "Operation": "Process",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 168,
  "PPID": 160,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-pkg-mngr-exec",
  "ProcessName": "/usr/bin/apt",
  "Resource": "/usr/bin/apt",
  "Result": "Permission denied",
  "Severity": "5",
  "Source": "/bin/bash",
  "Tags": "NIST,NIST_800-53_CM-7(4),SI-4,process,NIST_800-53_SI-4",
  "Timestamp": 1696318864,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T07:41:04.096412Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```