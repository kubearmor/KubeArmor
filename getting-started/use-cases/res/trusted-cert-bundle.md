#### Simulation
```sh
 kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd /etc/ssl/
root@mysql-74775b4bf4-65nqf:/etc/ssl# ls
certs
root@mysql-74775b4bf4-65nqf:/etc/ssl# rmdir certs
rmdir: failed to remove 'certs': Permission denied
root@mysql-74775b4bf4-65nqf:/etc/ssl# cd certs/
root@mysql-74775b4bf4-65nqf:/etc/ssl/certs# touch new
touch: cannot touch 'new': Permission denied
root@mysql-74775b4bf4-65nqf:/etc/ssl/certs#
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_RMDIR",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 24462,
  "HostPPID": 24411,
  "Labels": "app=mysql",
  "Message": "Credentials modification denied",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 185,
  "PPID": 179,
  "ParentProcessName": "/bin/bash",
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-trusted-cert-mod",
  "ProcessName": "/bin/rmdir",
  "Resource": "/etc/ssl/certs",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/bin/rmdir certs",
  "Tags": "MITRE,MITRE_T1552_unsecured_credentials,FGT1555,FIGHT",
  "Timestamp": 1696320102,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-03T08:01:42.373810Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```