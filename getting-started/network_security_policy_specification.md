# Specification of Network Security Policy for Nodes/VMs

## Policy Specification

The policy specification of KubeArmor Network Policy is similar to the specification of [Kubernetes Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) with a few changes. Here is the specification of a network security policy.

```text
apiVersion: security.kubearmor.com/v1
kind:KubeArmorNetworkPolicy
metadata:
  name: [policy name]

spec:
  severity: [1-10]                         # --> optional 
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  nodeSelector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

  ingress:
  - from:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp|FTP|ftp ...]
      port: [http|https|ssh|dns OR port number]
      endPort: [port number]

  egress:
  - to:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp|FTP|ftp ...]
      port: [http|https|ssh|dns OR port number]
      endPort: [port number]

  action: [Audit|Allow|Block]
```

## Policy Spec Description

Now, we will briefly explain how to define a host security policy.

* Common

  A security policy starts with the base information such as apiVersion, kind, and metadata. The apiVersion and kind would be the same in any security policies. In the case of metadata, you need to specify the name of a policy.

  ```text
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorNetworkPolicy
    metadata:
      name: [policy name]
  ```

  Make sure that you need to use `KubeArmorNetworkPolicy`.

* Severity

  You can specify the severity of a given policy from 1 to 10. This severity will appear in alerts when policy violations happen.

  ```text
  severity: [1-10]
  ```

* Tags

  The tags part is optional. You can define multiple tags (e.g., WARNING, SENSITIVE, MITRE, STIG, etc.) to categorize security policies.

  ```text
  tags: ["tag1", ..., "tagN"]
  ```

* Message

  The message part is optional. You can add an alert message, and then the message will be presented in alert logs.

  ```text
  message: [message]
  ```

* NodeSelector

  The node selector part is relatively straightforward. Similar to other Kubernetes configurations, you can specify \(a group of\) nodes based on labels.

  ```text
    nodeSelector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
  ```

  If you do not have any custom labels, you can use system labels as well.

  ```text
      kubernetes.io/arch: [architecture, (e.g., amd64)]
      kubernetes.io/hostname: [host name, (e.g., kubearmor-dev)]
      kubernetes.io/os: [operating system, (e.g., linux)]
  ```

* Ingress

  In the Ingress section, there are three types of matches: from, iface and ports. You can define source IP address ranges (IPv4 and IPv6) using the from. A list of network interfaces can be defined using iface. Destination port and protocol can be defined using ports. Port can be defined using name or number, protocol using name and an optional endPort can be defined to specify a port range (from port to endPort).

  ```text
  ingress:
  - from:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp|FTP|ftp ...]
      port: [http|https|ssh|dns OR port number]
      endPort: [port number]
  ```

* Egress

  Similarly in the Egress section, there are three types of matches: to, iface and ports. You can define destination IP address ranges (IPv4 and IPv6) using the to. A list of network interfaces can be defined using iface. Destination port and protocol can be defined using ports. port can be defined using name or number, protocol using name and an optional endPort can be defined to specify a port range (from port to endPort).

  ```text
  egress:
  - to:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|ICMP|icmp|FTP|ftp ...]
      port: [http|https|ssh|dns OR port number]
      endPort: [port number]
  ```

* Action

  The action could be Audit, Allow or Block.

  ```text
    action: [Allow|Audit|Block]
  ```