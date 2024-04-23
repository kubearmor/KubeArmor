#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd sbin
root@mysql-74775b4bf4-65nqf:/sbin# touch file
touch: cannot touch 'file': Permission denied
root@mysql-74775b4bf4-65nqf:/sbin# cd ..
```


### Expected Alert
```
{
  "ATags": [
    "NIST",
    "NIST_800-53_AU-2",
    "NIST_800-53_SI-4",
    "MITRE",
    "MITRE_T1036_masquerading",
    "MITRE_T1565_data_manipulation"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_OPEN flags=O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK",
  "Enforcer": "AppArmor",
  "HashID": "f0b220bfa3b7aeae754f3bf8a60dd1a0af001f5956ad22f625bdf83406a7fea3",
  "HostName": "aditya",
  "HostPID": 16462,
  "HostPPID": 16435,
  "Labels": "app=mysql",
  "Message": "Detected and prevented compromise to File integrity",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 167,
  "PPID": 160,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-file-integrity-monitoring",
  "ProcessName": "/bin/touch",
  "Resource": "/sbin/file",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/usr/bin/touch file",
  "Tags": "NIST,NIST_800-53_AU-2,NIST_800-53_SI-4,MITRE,MITRE_T1036_masquerading,MITRE_T1565_data_manipulation",
  "Timestamp": 1696316210,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T06:56:50.829165Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```