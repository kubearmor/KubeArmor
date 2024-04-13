#### Simulation
Set the default security posture to default-deny

```sh
kubectl annotate ns default kubearmor-network-posture=block --overwrite
```

```sh
kubectl exec -it nginx-77b4fdf86c-x7sdm -- bash
root@nginx-77b4fdf86c-x7sdm:/# curl www.google.com
curl: (6) Could not resolve host: www.google.com
root@nginx-77b4fdf86c-x7sdm:/# wget https://github.com/kubearmor/KubeArmor/blob/main/examples/wordpress-mysql/original/wordpress-mysql-deployment.yaml
--2023-10-06 11:08:58--  https://github.com/kubearmor/KubeArmor/blob/main/examples/wordpress-mysql/original/wordpress-mysql-deployment.yaml
Resolving github.com (github.com)... 20.207.73.82
Connecting to github.com (github.com)|20.207.73.82|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15051 (15K) [text/plain]
Saving to: 'wordpress-mysql-deployment.yaml.2'

wordpress-mysql-deployment.ya 100%[=================================================>]  14.70K  --.-KB/s    in 0.08s

2023-10-06 11:08:59 (178 KB/s) - 'wordpress-mysql-deployment.yaml.2' saved [15051/15051]
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
  "HostPID": 73952,
  "HostPPID": 73945,
  "Labels": "app=nginx",
  "NamespaceName": "default",
  "Operation": "Network",
  "Owner": {
    "Name": "nginx",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 532,
  "PPID": 525,
  "ParentProcessName": "/usr/bin/bash",
  "PodName": "nginx-77b4fdf86c-x7sdm",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/bin/curl",
  "Resource": "domain=AF_INET type=SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
  "Result": "Permission denied",
  "Source": "/usr/bin/curl www.google.com",
  "Timestamp": 1696588301,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-06T10:31:41.935146Z",
  "cluster_id": "4291",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```