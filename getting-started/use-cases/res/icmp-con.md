#### Simulation
```sh
kubectl exec -it nginx-77b4fdf86c-x7sdm -- bash
root@nginx-77b4fdf86c-x7sdm:/# hping3 www.google.com
Unable to resolve 'www.google.com'
root@nginx-77b4fdf86c-x7sdm:/# hping3 127.0.0.1
Warning: Unable to guess the output interface
[get_if_name] socket(AF_INET, SOCK_DGRAM, 0): Permission denied
[main] no such device
root@nginx-77b4fdf86c-x7sdm:/# ping google.com
PING google.com (216.58.200.206) 56(84) bytes of data.
64 bytes from nrt12s12-in-f206.1e100.net (216.58.200.206): icmp_seq=1 ttl=109 time=51.9 ms
64 bytes from nrt12s12-in-f206.1e100.net (216.58.200.206): icmp_seq=2 ttl=109 time=60.1 ms
^C
--- google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 51.917/56.005/60.094/4.088 ms
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "0-trust",
  "ContainerID": "20a6333c6a46e0da32b3062f0ba76e9aed4fc5ef51f5ee8aec5b980963cedea3",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:32da30332506740a2f7c34d5dc70467b7f14ec67d912703568daff790ab3f755",
  "ContainerName": "nginx",
  "Data": "syscall=SYS_SOCKET",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 86904,
  "HostPPID": 86860,
  "Labels": "app=nginx",
  "NamespaceName": "default",
  "Operation": "Network",
  "Owner": {
    "Name": "nginx",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 1064,
  "PPID": 1058,
  "ParentProcessName": "/usr/bin/bash",
  "PodName": "nginx-77b4fdf86c-x7sdm",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/sbin/hping3",
  "Resource": "domain=AF_INET type=SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
  "Result": "Permission denied",
  "Source": "/usr/sbin/hping3 www.google.com",
  "Timestamp": 1696593032,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-06T11:50:32.098937Z",
  "cluster_id": "4291",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```