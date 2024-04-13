#### Simulation

With a shell different than the user owning the file:
```sh
$ cat /etc/ca-certificates.conf                                                                                         
cat: /etc/ca-certificates.conf: Permission denied                                                                       
$                                                   
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "d3mo",
  "ContainerID": "548176888fca6bb6d66633794f3d5f9d54930a9d9f43d4f05c11de821c758c0f",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_OPEN flags=O_RDONLY",
  "Enforcer": "AppArmor",
  "HostName": "master-node",
  "HostPID": 39039,
  "HostPPID": 38787,
  "Labels": "app=wordpress",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "wordpress",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 220,
  "PPID": 219,
  "ParentProcessName": "/bin/dash",
  "PodName": "wordpress-fb448db97-wj7n7",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/bin/cat",
  "Resource": "/etc/ca-certificates.conf",
  "Result": "Permission denied",
  "Source": "/bin/cat /etc/ca-certificates.conf",
  "Timestamp": 1696485467,
  "Type": "MatchedPolicy",
  "UID": 1000,
  "UpdatedTime": "2023-10-05T05:57:47.935622Z",
  "cluster_id": "2302",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```