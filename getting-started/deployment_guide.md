# Getting Started Guide

This guide assumes you have access to a [k8s cluster](support_matrix.md). If you want to try non-k8s mode, for instance systemd mode to protect/audit containers or processes on VMs/bare-metal, check [here](kubearmor_vm.md).

Check the [KubeArmor support matrix](support_matrix.md) to verify if your platform is supported.

## Install KubeArmor
```
helm repo add kubearmor https://kubearmor.github.io/charts
helm repo update kubearmor
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/pkg/KubeArmorOperator/config/samples/sample-config.yml
```

You can find more details about helm related values and configurations [here](https://github.com/kubearmor/KubeArmor/tree/main/deployments/helm/KubeArmorOperator).

## Install kArmor CLI (Optional)

```
curl -sfL http://get.kubearmor.io/ | sudo sh -s -- -b /usr/local/bin
# sudo access is needed to install it in /usr/local/bin directory. But, if you prefer not to use sudo, you can install it in a different directory which is in your PATH.
```

> [!NOTE] 
> kArmor CLI provides a Developer Friendly way to interact with KubeArmor Telemetry. You can stream KubeArmor telemetry independently of kArmor CLI tool and integrate it with your chosen SIEM (Security Information and Event Management) solutions. [Here's a guide](https://github.com/kubearmor/kubearmor-relay-server/blob/main/README.md#streaming-kubearmor-telemetry-to-external-siem-tools) on how to achieve this integration. This guide assumes you have kArmor CLI to access KubeArmor Telemetry but you can view it on your SIEM tool once integrated.

## Deploy test nginx app

```
kubectl create deployment nginx --image=nginx
POD=$(kubectl get pod -l app=nginx -o name)
```

> [!NOTE] 
> `$POD` is used to refer to the target nginx pod in many cases below.


## Sample policies

<details>
  <summary><h4>Deny execution of package management tools (apt/apt-get)</h4></summary>

Package management tools can be used in the runtime env to download new binaries that will increase the attack surface of the pods. Attackers use package management tools to download accessory tooling (such as `masscan`) to further their cause. It is better to block usage of package management tools in production environments.

Lets apply the policy to block such execution:

```
cat <<EOF | kubectl apply -f -
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-pkg-mgmt-tools-exec
spec:
  selector:
    matchLabels:
      app: nginx
  process:
    matchPaths:
    - path: /usr/bin/apt
    - path: /usr/bin/apt-get
  action:
    Block
EOF
```

Now execute the `apt` command to download the `masscan` tool.
```
kubectl exec -it $POD -- bash -c "apt update && apt install masscan"
```

It will be denied permission to execute.

```
sh: 1: apt: Permission denied
command terminated with exit code 126
```

If you don't see Permission denied please refer [here](FAQ.md#debug-kubearmor-installation-issue-in-dockerized-kubernetes-environment) to debug this issue

</details>

<details>
  <summary><h4>Get policy violations notifications using kArmor CLI</h4></summary>

```
karmor logs -n default --json
```

```json
{
  "Timestamp": 1686475183,
  "UpdatedTime": "2023-06-11T09:19:43.451704Z",
  "ClusterName": "default",
  "HostName": "ip-172-31-24-142",
  "NamespaceName": "default",
  "PodName": "nginx-8f458dc5b-fl42t",
  "Labels": "app=nginx",
  "ContainerID": "8762eafc25a35ab90089f79703b86659989e8e547c2c029fb60f55d884355000",
  "ContainerName": "nginx",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:af296b188c7b7df99ba960ca614439c99cb7cf252ed7bbc23e90cfda59092305",
  "HostPPID": 3341922,
  "HostPID": 3341928,
  "PPID": 786,
  "PID": 792,
  "ParentProcessName": "/bin/dash",
  "ProcessName": "/usr/bin/apt",
  "PolicyName": "block-pkg-mgmt-tools-exec",
  "Severity": "1",
  "Type": "MatchedPolicy",
  "Source": "/bin/dash",
  "Operation": "Process",
  "Resource": "/usr/bin/apt update",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Permission denied"
}
```

</details>

<details>
  <summary><h4>Deny access to service account token</h4></summary>

K8s mounts the service account token by default in each pod even if there is no app using it. Attackers use these service account tokens to do lateral movements.

For e.g., to access service account token:
```
❯ kubectl exec -it $POD -- bash
(inside pod) $ curl https://$KUBERNETES_PORT_443_TCP_ADDR/api --insecure --header "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)"
{                                
  "kind": "APIVersions",      
  "versions": [                 
    "v1"                      
  ],                          
  "serverAddressByClientCIDRs": [
    {
      "clientCIDR": "0.0.0.0/0",
      "serverAddress": "ip-10-0-48-51.us-east-2.compute.internal:443"
    }
  ]
}
```
Thus we can see that one can use the service account token to access the Kube API server.

Lets apply a policy to block access to service account token:
```
cat <<EOF | kubectl apply -f -
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-service-access-token-access
spec:
  selector:
    matchLabels:
      app: nginx
  file:
    matchDirectories:
    - dir: /run/secrets/kubernetes.io/serviceaccount/
      recursive: true
  action:
    Block
EOF
```

Now when anyone tries to access to service account token, it would be `Permission Denied`.

```
❯ kubectl exec -it $POD -- bash
(inside pod) $ curl https://$KUBERNETES_PORT_443_TCP_ADDR/api --insecure --header "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)"
cat: /run/secrets/kubernetes.io/serviceaccount/token: Permission denied
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/api\"",
  "reason": "Forbidden",
  "details": {},
  "code": 403
}
```

If you don't see Permission denied please refer [here](FAQ.md#debug-kubearmor-installation) to debug this issue.


</details>

<details>
  <summary><h4>Audit access to folders/paths</h4></summary>

Access to certain folders/paths might have to be audited for compliance/reporting reasons.

File Visibility is disabled by default to minimize telemetry. Some file based policies will need that enabled. To enable file visibility on a namespace level:
```
kubectl annotate ns default kubearmor-visibility="process,file,network" --overwrite
```

For more details on this: https://docs.kubearmor.io/kubearmor/documentation/kubearmor_visibility#updating-namespace-visibility

Lets audit access to `/etc/nginx/` folder within the deployment.
```
cat <<EOF | kubectl apply -f -
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: audit-etc-nginx-access
spec:
  selector:
    matchLabels:
      app: nginx
  file:
    matchDirectories:
    - dir: /etc/nginx/
      recursive: true  
  action:
    Audit
EOF
```

> Note: `karmor logs -n default` would show all the audit/block operations.

```json
{
  "Timestamp": 1686478371,
  "UpdatedTime": "2023-06-11T10:12:51.967519Z",
  "ClusterName": "default",
  "HostName": "ip-172-31-24-142",
  "NamespaceName": "default",
  "PodName": "nginx-8f458dc5b-fl42t",
  "Labels": "app=nginx",
  "ContainerID": "8762eafc25a35ab90089f79703b86659989e8e547c2c029fb60f55d884355000",
  "ContainerName": "nginx",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:af296b188c7b7df99ba960ca614439c99cb7cf252ed7bbc23e90cfda59092305",
  "HostPPID": 3224933,
  "HostPID": 3371357,
  "PPID": 3224933,
  "PID": 825,
  "ParentProcessName": "/x86_64-bottlerocket-linux-gnu/sys-root/usr/bin/containerd-shim-runc-v2",
  "ProcessName": "/bin/cat",
  "PolicyName": "audit-etc-nginx-access",
  "Severity": "1",
  "Type": "MatchedPolicy",
  "Source": "/bin/cat /etc/nginx/conf.d/default.conf",
  "Operation": "File",
  "Resource": "/etc/nginx/conf.d/default.conf",
  "Data": "syscall=SYS_OPENAT fd=-100 flags=O_RDONLY",
  "Enforcer": "eBPF Monitor",
  "Action": "Audit",
  "Result": "Passed"
}
```

</details>

<details>
  <summary><h4>Zero Trust Least Permissive Policy: Allow only nginx to execute in the pod, deny rest</h4></summary>

Least permissive policies require one to allow certain actions/operations and deny rest. With KubeArmor it is possible to specify as part of the policy as to what actions should be allowed and deny/audit the rest.

[Security Posture](default_posture.md) defines what happens to the operations that are not in the allowed list. Should it be audited (allow but alert), or denied (block and alert)?

By default the security posture is set to audit. Lets change the security posture to default deny.
```
kubectl annotate ns default kubearmor-file-posture=block --overwrite
```
```
cat <<EOF | kubectl apply -f -
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: only-allow-nginx-exec
spec:
  selector:
    matchLabels:
      app: nginx
  file:
    matchDirectories:
    - dir: /
      recursive: true  
  process:
    matchPaths:
    - path: /usr/sbin/nginx
    - path: /bin/bash
  action:
    Allow
EOF
```

Observe that the policy contains `Allow` action. Once there is any KubeArmor policy having `Allow` action then the pods enter least permissive mode, allowing only explicitly allowed operations.

> Note: Use `kubectl port-forward $POD --address 0.0.0.0 8080:80` to access nginx and you can see that the nginx web access still works normally.

Lets try to execute some other processes:
```
kubectl exec -it $POD -- bash -c "chroot"
```
Any binary other than `bash` and `nginx` would be permission denied.

If you don't see Permission denied please refer [here](FAQ.md#debug-kubearmor-installation) to debug this issue

</details>
