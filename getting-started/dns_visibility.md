# DNS Visibility

KubeArmor supports DNS visibility for egress traffic at both pod level and host level.

To gain the visibility, it uses `kprobe/udp_sendmsg` to access the payload of a DNS packet sent over a UDP connection. It provides these three information retrieved from the DNS query payload:

1. Domain name
2. Destination address (DNS server)
3. Qtype (DNS record type) [A: IPv4 address, AAAA: IPv6 address]

To enable DNS visibility, KubeArmor supports `dns` as a visibility flag. You can enable it at pod, namespace, or global level. See [KubeArmor visibility](./kubearmor_visibility.md) for more details.

## Example

1. #### Annotate namespace to enable DNS visibility

```shell
kubectl annotate ns default kubearmor-visibility=process,network,dns
```

2. #### Create a deployment in default namespace

```shell
kubectl create deployment nginx --image nginx
```

3. #### Watch logs in another terminal

```shell
karmor logs --logFilter all --operation Network --namespace default
```

4. #### Generate a DNS query event

```shell
root@nginx-779797d5bd-wlrsn:/# curl google.com
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
```

5. #### Observe telemetry logs with `kfunc=UDP_SENDMSG` in `Data` field

```json
[
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.125539Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.default.svc.cluster.local,daddr=10.43.0.10,qtype=AAAA",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.default.svc.cluster.local,daddr=10.43.0.10,qtype=AAAA",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.125535Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.default.svc.cluster.local,daddr=10.43.0.10,qtype=A",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.default.svc.cluster.local,daddr=10.43.0.10,qtype=A",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.126117Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.svc.cluster.local,daddr=10.43.0.10,qtype=A",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.svc.cluster.local,daddr=10.43.0.10,qtype=A",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.126209Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.svc.cluster.local,daddr=10.43.0.10,qtype=AAAA",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.svc.cluster.local,daddr=10.43.0.10,qtype=AAAA",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.126649Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.cluster.local,daddr=10.43.0.10,qtype=AAAA",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.cluster.local,daddr=10.43.0.10,qtype=AAAA",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.126645Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com.cluster.local,daddr=10.43.0.10,qtype=A",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com.cluster.local,daddr=10.43.0.10,qtype=A",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.126997Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com,daddr=10.43.0.10,qtype=A",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com,daddr=10.43.0.10,qtype=A",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  },
  {
    "Timestamp": 1765218527,
    "UpdatedTime": "2025-12-08T18:28:47.127080Z",
    "ClusterName": "default",
    "HostName": "archlinux",
    "NamespaceName": "default",
    "Owner": {
      "Ref": "Deployment",
      "Name": "nginx",
      "Namespace": "default"
    },
    "PodName": "nginx-779797d5bd-wlrsn",
    "Labels": "app=nginx",
    "ContainerID": "c830ee7121da37bde4021a90d51728d05bf2e71ac5a31b6461a39b7cf77cffb1",
    "ContainerName": "nginx",
    "ContainerImage": "docker.io/library/nginx:latest@sha256:553f64aecdc31b5bf944521731cd70e35da4faed96b2b7548a3d8e2598c52a42",
    "ParentProcessName": "/usr/bin/bash",
    "ProcessName": "/usr/bin/curl",
    "HostPPID": 247074,
    "HostPID": 251151,
    "PPID": 41,
    "PID": 51,
    "UID": 0,
    "Type": "ContainerLog",
    "Source": "/usr/bin/curl google.com",
    "Operation": "Network",
    "Resource": "sa_family=AF_INET sin_port=53",
    "Data": "kfunc=UDP_SENDMSG,domain=google.com,daddr=10.43.0.10,qtype=AAAA",
    "EventData": {
      "Kfunc": "UDP_SENDMSG,domain=google.com,daddr=10.43.0.10,qtype=AAAA",
      "Sa_family": "AF_INET",
      "Sin_port": "53"
    },
    "Result": "Passed",
    "Cwd": "/",
    "TTY": "pts0",
    "ExecEvent": {
      "ExecID": "1078688820741427",
      "ExecutableName": "curl"
    }
  }
]
```