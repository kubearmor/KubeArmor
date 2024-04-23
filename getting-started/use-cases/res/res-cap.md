#### Simulation
```sh
root@ubuntu-1-deployment-f987bd4d6-xzcb8:/# tcpdump
tcpdump: eth0: You don't have permission to capture on that device
(socket: Operation not permitted)
root@ubuntu-1-deployment-f987bd4d6-xzcb8:/#    
```

#### Expected Alert
```
{
    "Action":"Block",
    "ClusterName":"k3sn0d3",
    "ContainerID":"aaf2118edcc20b3b04a0fae6164f957993bf3c047fd8cb33bc37ac7d0175e848",
    "ContainerImage":"docker.io/kubearmor/ubuntu-w-utils:0.1@sha256:b4693b003ed1fbf7f5ef2c8b9b3f96fd853c30e1b39549cf98bd772fbd99e260",
    "ContainerName":"ubuntu-1-container",
    "Data":"syscall=SYS_SOCKET",
    "Enforcer":"AppArmor",
    "HashID":"dd12f0f12a75b30d47c5815f93412f51b259b74ac0eccc9781b6843550f694a3",
    "HostName":"worker-node02",
    "HostPID":38077,
    "HostPPID":38065,
    "Labels":"container=ubuntu-1 group=group-1",
    "Message":"",
    "NamespaceName":"multiubuntu",
    "Operation":"Network",
    "Owner":{
        "Name":"ubuntu-1-deployment",
        "Namespace":"multiubuntu",
        "Ref":"Deployment"
    },
    "PID":124,
    "PPID":114,
    "PodName":"ubuntu-1-deployment-f987bd4d6-xzcb8",
    "PolicyName":"ksp-ubuntu-1-cap-net-raw-block",
    "ProcessName":"/usr/sbin/tcpdump",
    "Resource":"domain=AF_PACKET type=SOCK_RAW protocol=768",
    "Result":"Operation not permitted",
    "Severity":"1",
    "Source":"/usr/sbin/tcpdump",
    "Tags":"",
    "Timestamp":1705405378,
    "Type":"MatchedPolicy",
    "UID":0,
    "UpdatedTime":"2024-01-16T11:42:58.662928Z",
    "UpdatedTimeISO":"2024-01-16T11:42:58.662Z",
    "cluster_id":"16402",
    "component_name":"kubearmor",
    "instanceGroup":"0",
    "instanceID":"0",
    "workload":"1"
}
```