# Default Posture

KubeArmor supports configurable default security posture. The security posture could be allow/audit/deny. Default Posture is used when there's atleast one `Allow` policy for the given deployment i.e. KubeArmor is handling policies in whitelisting manner (more about this in [Considerations in Policy Action](https://github.com/kubearmor/KubeArmor/blob/event-auditor/getting-started/consideration_in_policy_action.md) ).

There are two default mode of operations available `block` and `audit`. `block` mode blocks all the operations that are not allowed in the policy. `audit` generates telemetry events for operations that would have been blocked otherwise.

KubeArmor has 4 types of resources: Process, File, Network and Capabilities. Default Posture is configurable for each of the resources seperately except Process. Process based operations are treated under File resource only.
## Configuring Default Posture

### Global Default Posture

> **Note** By default, KubeArmor set the Global default posture to `audit`

Global default posture is configured using configuration options passed to KubeArmor using configuration file

```yaml
defaultFilePosture: block # or audit
defaultNetworkPosture: block # or audit
defaultCapabilitiesPosture: block # or audit
```

Or using command line flags with the KubeArmor binary

```sh
  -defaultFilePosture string
    	configuring default enforcement action in global file context [audit,block] (default "block")
  -defaultNetworkPosture string
    	configuring default enforcement action in global network context [audit,block] (default "block")
  -defaultCapabilitiesPosture string
    	configuring default enforcement action in global capability context [audit,block] (default "block")
```

### Namespace Default Posture

We use namespace annotations to configure default posture per namespace. Supported annotations keys are `kubearmor-file-posture`,`kubearmor-network-posture` and `kubearmor-capabilities-posture` with values `block` or `audit`. If a namespace is annotated with a supported key and an invalid value ( like `kubearmor-file-posture=invalid`), KubeArmor will update the value with the global default posture ( i.e. to `kubearmor-file-posture=block`).

## Example

Let's start KubeArmor with configuring default network posture to audit in the following YAML.

```sh
 sudo env KUBEARMOR_CFG=/path/to/kubearmor.yaml ./kubearmor
```

Contents of `kubearmor.yaml`
```yaml
defaultNetworkPosture: audit
```

Here's a sample policy to allow `tcp` connections from `curl` binary.
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-ubuntu-5-net-tcp-allow-curl
  namespace: multiubuntu
spec:
  severity: 8
  selector:
    matchLabels:
      container: ubuntu-5
  network:
    matchProtocols:
    - protocol: tcp
      fromSource:
      - path: /usr/bin/curl
  action:
    Allow
```
> Note: This example is in the [multiubuntu](https://github.com/kubearmor/KubeArmor/blob/main/examples/multiubuntu.md) environment.

Inside the `ubuntu-5-deployment`, if we try to access `tcp` using `curl`. It works as expected with no telemetry generated.
```sh
root@ubuntu-5-deployment-7778f46c67-hk6k6:/# curl 142.250.193.46
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
```

If we try to access `udp` using `curl`, a bunch of telemetry is generated for the `udp` access.
```sh
root@ubuntu-5-deployment-7778f46c67-hk6k6:/# curl google.com
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>
```
> `curl google.com` requires UDP for DNS resolution.

Generated alert has Policy Name `DefaultPosture` and Action as `Audit`
```sh
== Alert / 2022-03-21 12:56:32.999475 ==
Cluster Name: default
Host Name: kubearmor-dev-all
Namespace Name: multiubuntu
Pod Name: ubuntu-5-deployment-7778f46c67-hk6k6
Container ID: 1f92eb4c9d730862174be04f319763a2c1ac2752669807051c42ddc78aa102d1
Container Name: ubuntu-5-container
Policy Name: DefaultPosture
Type: MatchedPolicy
Source: /usr/bin/curl google.com
Operation: Network
Resource: domain=AF_INET6 type=SOCK_DGRAM protocol=0
Data: syscall=SYS_SOCKET
Action: Audit
Result: Passed
```

Now let's update the default network posture to block for `multiubuntu` namespace.

```sh
~❯❯❯  kubectl annotate ns multiubuntu kubearmor-network-posture=block
namespace/multiubuntu annotated
```

Now if we try to access `udp` using `curl`, the action is blocked and related alerts are generated.

```sh
root@ubuntu-5-deployment-7778f46c67-hk6k6:/# curl google.com
curl: (6) Could not resolve host: google.com
```

Here curl couldn't resolve google.com due to blocked access to UDP.

Generated alert has Policy Name `DefaultPosture` and Action as `Block`

```
== Alert / 2022-03-21 13:06:27.731918 ==
Cluster Name: default
Host Name: kubearmor-dev-all
Namespace Name: multiubuntu
Pod Name: ubuntu-5-deployment-7778f46c67-hk6k6
Container ID: 1f92eb4c9d730862174be04f319763a2c1ac2752669807051c42ddc78aa102d1
Container Name: ubuntu-5-container
Policy Name: ksp-ubuntu-5-net-tcp-allow
Severity: 8
Type: MatchedPolicy
Source: /usr/bin/curl google.com
Operation: Network
Resource: domain=AF_INET6 type=SOCK_DGRAM protocol=0
Data: syscall=SYS_SOCKET
Action: Allow
Result: Permission denied
```

Let's try to set the annotation value to something invalid.

```
~❯❯❯  kubectl annotate ns multiubuntu kubearmor-network-posture=invalid --overwrite
namespace/multiubuntu annotated
~❯❯❯  kubectl describe ns multiubuntu
Name:         multiubuntu
Labels:       kubernetes.io/metadata.name=multiubuntu
Annotations:  kubearmor-network-posture: audit
Status:       Active
```
We can see that, annotation value was automatically updated to audit since that was global mode of operation for network in the KubeArmor configuration.
