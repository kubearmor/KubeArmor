#### Simulation
```sh
kubectl exec -it dvwa-web-566855bc5b-4j4vl -- bash
root@dvwa-web-566855bc5b-4j4vl:/var/www/html# kubectl
bash: /usr/bin/kubectl: Permission denied
root@dvwa-web-566855bc5b-4j4vl:/var/www/html#
```

#### Expected Alert
```
{
  "ATags": null,
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "32015ebeea9e1f4d4e7dbf6608c010ef2b34c48f1af11a5c6f0ea2fd27c6ba6c",
  "ContainerImage": "docker.io/cytopia/dvwa:php-8.1@sha256:f7a9d03b1dfcec55757cc39ca2470bdec1618b11c4a51052bb4f5f5e7d78ca39",
  "ContainerName": "dvwa",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HashID": "1167b21433f2a4e78a4c6875bb34232e6a2b3c8535e885bb4f9e336fd2801d92",
  "HostName": "aditya",
  "HostPID": 38035,
  "HostPPID": 37878,
  "Labels": "tier=frontend,app=dvwa-web",
  "Message": "",
  "NamespaceName": "default",
  "Operation": "Process",
  "Owner": {
    "Name": "dvwa-web",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 554,
  "PPID": 548,
  "PodName": "dvwa-web-566855bc5b-4j4vl",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/bin/kubectl",
  "Resource": "/usr/bin/kubectl",
  "Result": "Permission denied",
  "Severity": "",
  "Source": "/bin/bash",
  "Tags": "",
  "Timestamp": 1696326880,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T09:54:40.056501Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```