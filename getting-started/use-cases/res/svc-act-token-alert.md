#### Simulation
```sh
root@wordpress-7c966b5d85-42jwx:/# cd /run/secrets/kubernetes.io/serviceaccount/ 
root@wordpress-7c966b5d85-42jwx:/run/secrets/kubernetes.io/serviceaccount# ls 
ls: cannot open directory .: Permission denied 
root@wordpress-7c966b5d85-42jwx:/run/secrets/kubernetes.io/serviceaccount# 
```

#### Expected Alert
```
{
  "ATags": null,
  "Action": "Block",
  "ClusterName": "deathiscoming",
  "ContainerID": "bbf968e6a75f0b4412478770911c6dd05d5a83ec97ca38872246e89c31e9d41a",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC",
  "Enforcer": "AppArmor",
  "HashID": "f1c272d8d75bdd91b9c4d1dc74c8d0f222bf4ecd0008c3a22a54706563ec5827",
  "HostName": "aditya",
  "HostPID": 11105,
  "HostPPID": 10997,
  "Labels": "app=wordpress",
  "Message": "",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "",
    "Namespace": "",
    "Ref": ""
  },
  "PID": 204,
  "PPID": 194,
  "PodName": "wordpress-7c966b5d85-42jwx",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/bin/ls",
  "Resource": "/run/secrets/kubernetes.io/serviceaccount",
  "Result": "Permission denied",
  "Severity": "",
  "Source": "/bin/ls",
  "Tags": "",
  "Timestamp": 1695903189,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-09-28T12:13:09.159252Z",
  "cluster_id": "3664",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```
