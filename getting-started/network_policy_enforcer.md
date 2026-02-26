# Network Policy Enforcer

The Network Policy Enforcer is a network security module for KubeArmor that provides granular control over network traffic at the host and node level. It allows administrators to restrict or audit network communications based on IP addresses, CIDR blocks, ports, protocols, and specific network interfaces.

It acts as a **stateful** firewall. This means if an outbound request is permitted by an egress policy, the corresponding inbound response packets are automatically allowed. You do not need to write explicit, bidirectional rules for standard request-response traffic.

To enable or disable the Network Policy Enforcer, configure the `enableNetworkPolicyEnforcer` flag in your KubeArmor configuration.

You can define policies that enforce actions on ingress and egress network traffic.
See the policy spec [here](network_security_policy_specification.md).

## How it works

1. The Network Policy Enforcer is built on top of `nftables`, the new in-kernel packet classification framework that replaces the legacy `iptables`. It provides high performance, stateful connection tracking, and rule evaluation directly within the kernel.

2. When a user applies a KubeArmor network policy, the enforcer translates the YAML specification into optimized nftables rules.

3. For traffic that needs to be logged, whether due to an explicit policy (Audit/Block) or the host logs or default posture logs, a specific log prefix is appended to the nftables rule. 

    This prefix string contains 
    * the policy name, 
    * the traffic direction (INPUT for ingress or OUTPUT for egress), 
    * and the enforced action (Audit or Block)

4. Packets matching Allow policies are allowed to pass silently. However, when a packet matches an Audit or Block rule, the kernel sends the packet information and the log prefix. This is sent to userspace over a Netlink socket. KubeArmor listens on this socket, parses the prefix and packet information, and generates rich, standard telemetry alerts.

## Default Throttling

To protect the user from being overwhelmed by high-frequency network events (e.g., a port scan, retires or a denial-of-service attempt), the enforcer implements a built-in rate-limiting cache.

KubeArmor stores every generated network firewall log in a local cache. The cache key is generated using the network flow information combined with the log prefix. When a new log arrives, KubeArmor checks the cache. If an identical log was recorded less than 10 seconds ago, the new log is dropped. If the time difference is greater than 10 seconds, the timestamp in the cache is updated, and the log is sent to the feeder. A background routine also runs periodically to delete log entries that are older than 1 minute.

## Enforcement Mode

If there is at least one Allow rule, the enforcer operates in Allowlist Mode. Packets not matching any policy will have their behavior decided by the host default network posture. It can be `audit` or `block` (default is `block`).

You can configure this using the `hostDefaultNetworkPosture` flag.

---

**NOTE**

Loopback Traffic is Always Allowed: Network Policy Enforcer hardcodes an accept rule for all traffic on the loopback interface.

**Why?** Blocking loopback traffic almost universally breaks the host system. Communication happening between services running on the host rely over the loopback interface. KubeArmor ensures this internal traffic is never disrupted by user-defined network policies.

