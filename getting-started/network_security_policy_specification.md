# Specification of Network Security Policy for Nodes/VMs

## Policy Specification

The policy specification of KubeArmor Network Policy is similar to the specification of [Kubernetes Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) with a few changes. Here is the specification of a network security policy.

```text
apiVersion: security.kubearmor.com/v1
kind:KubeArmorNetworkPolicy
metadata:
  name: [policy name]
  namespace: [namespace name]              # --> only for pod policies (selector)

spec:
  severity: [1-10]                         # --> optional 
  tags: ["tag", ...]                       # --> optional
  message: [message]                       # --> optional

  nodeSelector:                            # --> either nodeSelector (host) or selector (pods)
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

  selector:
    matchLabels:
      [key1]: [value1]
      [keyN]: [valueN]

  level: [Pod|Policy]                      # --> optional (default: Pod, only for selector)

  ingress:
  - from:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|SCTP|sctp]
      port: [http|https|ssh|dns OR "port number"]
      endPort: [port number]
    limit: [bandwidth quota (e.g., 500KB, 10MB, 2GB)]   # --> optional
    duration: [quota reset interval (e.g., 45s, 30m, 2h)] # --> optional

  egress:
  - to:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|SCTP|sctp]
      port: [http|https|ssh|dns OR "port number"]
      endPort: [port number]
    limit: [bandwidth quota (e.g., 500KB, 10MB, 2GB)]   # --> optional
    duration: [quota reset interval (e.g., 45s, 30m, 2h)] # --> optional

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

  KubeArmor supports the following hostname label matching modes for Node/VM policies:

  | Mode | Example | Description |
  |---|---|---|
  | Exact | `kubearmor.io/hostname: kubearmor-dev` | Targets a specific node by name |
  | Wildcard | `kubearmor.io/hostname: "*"` | Targets all Nodes/VMs |
  | Comma-separated | `kubernetes.io/hostname: node-1,node-2` | Targets multiple specific nodes |
  | Regex | `kubearmor.io/hostnamereg: node-*` | Targets nodes whose hostname matches a pattern |

  > **Note:** `kubernetes.io/` prefix variants are only available in Kubernetes environments. The `hostnamereg` label is supported with both `kubearmor.io/` and `kubernetes.io/` prefixes.

* Selector

  Instead of a node selector, you can use the selector to apply a policy to pods. Pods in the namespace of the policy (`metadata.namespace`) are selected based on their labels.

  ```text
    selector:
      matchLabels:
        [key1]: [value1]
        [keyN]: [valueN]
  ```

  > **Note:** Policies targeting pods only support bandwidth quota rules, i.e., each ingress/egress rule needs to specify both `limit` and `duration`. See [Network Bandwidth Quotas](network_bandwidth_quota.md) for details.

* Level

  The level part is optional and defines the scope of bandwidth quota enforcement for policies using the selector. The supported values are `Pod` and `Policy` (`pod` and `policy` are also accepted). If not specified, `Pod` is used.

  ```text
    level: [Pod|Policy]
  ```

  | Level | Description |
  |---|---|
  | `Pod` (default) | Each selected pod gets its own isolated quota counter. |
  | `Policy` | All selected pods share a single, combined quota counter. |

  The level is ignored for host policies (nodeSelector), where the quota is applied to the node as a whole.

* Ingress

  In the Ingress section, there are three types of matches: from, iface and ports. You can define source IP address ranges (IPv4 and IPv6) using the from. A list of network interfaces can be defined using iface. Destination port and protocol can be defined using ports. Port (string) can be defined using name or number, protocol using name and an optional endPort can be defined to specify a port range (from port to endPort).

  ```text
  ingress:
  - from:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|SCTP|sctp]
      port: [http|https|ssh|dns OR "port number"]
      endPort: [port number]
    limit: [bandwidth quota]
    duration: [quota reset interval]
  ```

* Egress

  Similarly in the Egress section, there are three types of matches: to, iface and ports. You can define destination IP address ranges (IPv4 and IPv6) using the to. A list of network interfaces can be defined using iface. Destination port and protocol can be defined using ports. Port (string) can be defined using name or number, protocol using name and an optional endPort can be defined to specify a port range (from port to endPort).

  ```text
  egress:
  - to:
    - ipBlock:
        cidr: [IP address range]
    iface: [if1, ...]
    ports:
    - protocol: [TCP|tcp|UDP|udp|SCTP|sctp]
      port: [http|https|ssh|dns OR "port number"]
      endPort: [port number]
    limit: [bandwidth quota]
    duration: [quota reset interval]
  ```

* Limit and Duration

  The limit and duration parts are optional and can be set in any ingress or egress rule to define a network bandwidth quota. Both of them need to be specified together; otherwise, no quota is enforced.

  * `limit` is the total amount of data allowed for the rule (inbound for ingress, outbound for egress). It must be a number followed by an optional unit: `KB` (or `K`), `MB` (or `M`), or `GB` (or `G`), e.g., `500KB`, `10MB`, `2GB`. If no unit is given, `GB` is used.
  * `duration` is the time interval after which the quota counter is reset. It accepts Go duration strings, such as `45s`, `30m`, `2h`, or `1h30m`.

  ```text
  egress:
  - limit: "2MB"
    duration: "20m"
  ```

  Once the limit is exceeded within the duration window, traffic matching the rule is dropped if the action is `Block`, or a single alert is generated without dropping traffic if the action is `Audit`. The quota is reset at the end of the duration window. For more details and examples, see [Network Bandwidth Quotas](network_bandwidth_quota.md).

* Action

  The action could be Audit, Allow or Block.

  ```text
    action: [Allow|Audit|Block]
  ```