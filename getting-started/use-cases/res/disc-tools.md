#### Simulation
```sh
kubectl exec -it dvwa-web-566855bc5b-xtgwq -- bash
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# netstat
bash: /bin/netstat: Permission denied
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# ifconfig
bash: /sbin/ifconfig: Permission denied
root@dvwa-web-566855bc5b-xtgwq:/var/www/html#
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# arp
bash: /usr/sbin/arp: Permission denied
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "no-trust",
  "ContainerID": "e8ac2e227d293e76ab81a34945b68f72a2618ed3275ac64bb6a82f9cd2d014f1",
  "ContainerImage": "docker.io/cytopia/dvwa:php-8.1@sha256:f7a9d03b1dfcec55757cc39ca2470bdec1618b11c4a51052bb4f5f5e7d78ca39",
  "ContainerName": "dvwa",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 35592,
  "HostPPID": 35557,
  "Labels": "tier=frontend,app=dvwa-web",
  "Message": "Network service has been scanned!",
  "NamespaceName": "default",
  "Operation": "Process",
  "Owner": {
    "Name": "dvwa-web",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 989,
  "PPID": 983,
  "ParentProcessName": "/bin/bash",
  "PodName": "dvwa-web-566855bc5b-npjn8",
  "PolicyName": "harden-dvwa-web-network-service-scanning",
  "ProcessName": "/bin/netstat",
  "Resource": "/bin/netstat",
  "Result": "Permission denied",
  "Severity": "5",
  "Source": "/bin/bash",
  "Tags": "MITRE,FGT1046,CIS",
  "Timestamp": 1696501152,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-05T10:19:12.809606Z",
  "cluster_id": "4225",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```