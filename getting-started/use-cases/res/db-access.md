#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd var/lib/mysql
root@mysql-74775b4bf4-65nqf:/var/lib/mysql# cat ib_logfile1
cat: ib_logfile1: Permission denied
root@mysql-74775b4bf4-65nqf:/var/lib/mysql#
```

#### Expected Alert
```
{
  "ATags": [
    "CIS",
    "CIS_Linux"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_OPEN flags=O_RDONLY",
  "Enforcer": "AppArmor",
  "HashID": "a7b7d91d52de395fe6cda698e89e0112e6f3ab818ea331cee60295a8ede358c8",
  "HostName": "aditya",
  "HostPID": 29898,
  "HostPPID": 29752,
  "Labels": "app=mysql",
  "Message": "Alert! Attempt to make changes to database detected",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 230,
  "PPID": 223,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "ksp-block-mysql-dir",
  "ProcessName": "/bin/cat",
  "Resource": "/var/lib/mysql/ib_logfile1",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/bin/cat ib_logfile1",
  "Tags": "CIS,CIS_Linux",
  "Timestamp": 1696322555,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T08:42:35.618890Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```