# Network Bandwidth Quotas in KubeArmor

KubeArmor supports high-performance, kernel-enforced network bandwidth limits (for both `Ingress` and `Egress`) utilizing `nftables` named quotas. This feature enables users to protect workloads from exceeding network bandwidth, and establish strict network resource limits at either individual Pod boundaries or across shared policy boundaries.

---

## 🛠️ How to Define and Apply Quota Policies

To configure network bandwidth limits, KubeArmor dynamically leverages the standard `KubeArmorNetworkPolicy` spec, supporting two fields inside its ingress/egress rules:
1. **`limit`**: Declares the total data bandwidth threshold (e.g., `10MB`, `500KB`, `2GB`).
2. **`duration`**: Declares the time interval before the quota is reset (e.g., `10s`, `1m`, `2h`).

KubeArmor automatically derives the enforcement boundary based on your policy selector configuration. Click on each section below to expand its details:

<details>
<summary><b>1. Pod-Level Quota Policy (Per-Pod Quotas)</b></summary>

*   **Identification**: Automatically detected if your policy defines selector labels (targeting Pod workloads inside the namespace) and sets `level: Pod` (or leaves it empty, which defaults to `Pod`).
*   **Behavior**: Each matching pod receives its own private, isolated bandwidth quota counter.
*   **Use Case**: Prevent database pods from sending more than 2MB of egress data within a 20-minute window. If you target 3 database pods, each gets its own independent 2MB limit.

**Policy Example:**
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorNetworkPolicy
metadata:
  name: quota-test-policy
  namespace: multiubuntu
spec:
  selector:
    matchLabels:
      app: quota-test-pod
  action: Block
  level: Pod # <-- Isolated per-pod tracking
  egress:
  - limit: "2MB" 
    duration: "20m" 
```

**Corresponding Telemetry Alert Log:**
When the 2MB egress limit for an individual pod is exceeded, KubeArmor blocks subsequent traffic for that specific pod and generates the following telemetry alert, showing that the enforcement **`QuotaLevel` is set to `pod`**:

```text
== Alert / 2026-05-25 04:14:59.566130 ==
ClusterName: default
HostName: aryan
NamespaceName: multiubuntu
PodName: quota-test-deployment-5bc54c58b9-4rpvw
Labels: app=quota-test-pod
Type: MatchedNetworkPolicy
PolicyName: quota-test-policy
Resource: EGRESS
Operation: NetworkFirewall
Action: Block
Data: SourceIP=10.42.0.233 SourcePort=0 DestinationIP=8.8.8.8 DestinationPort=0 Protocol=ICMP QuotaLevel=pod QuotaLimit=2MB
EventData: map[DestinationIP:8.8.8.8 DestinationPort:0 Protocol:ICMP QuotaLevel:pod QuotaLimit:2MB SourceIP:10.42.0.233 SourcePort=0]
Enforcer: NetworkPolicyEnforcer
Result: Permission denied
ExecEvent: map[]
PPID: 0
UID: 0
```

</details>

<br>

<details>
<summary><b>2. Policy-Level Quota Policy (Shared Global Quotas)</b></summary>

*   **Identification**: Automatically detected if your policy targets container workloads and explicitly declares `level: Policy`.
*   **Behavior**: All selected pods matching the selector labels share a single, combined bandwidth quota counter.
*   **Use Case**: Protect shared downstream resources. The combined egress traffic across all targeted pods cannot exceed 2MB within a 20-minute window.

**Policy Example:**
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorNetworkPolicy
metadata:
  name: quota-test-policy
  namespace: multiubuntu
spec:
  selector:
    matchLabels:
      app: quota-test-pod
  action: Block
  level: Policy # <-- Shared across all selected pods
  egress:
  - limit: "2MB" 
    duration: "20m" 
```

**Corresponding Telemetry Alert Log:**
When the shared 2MB egress limit is exceeded, KubeArmor blocks subsequent traffic across all matched pods and instantly generates the following telemetry alert, showing that the enforcement **`QuotaLevel` is set to `policy`**:

```text
Created a gRPC client (:32767)
Checked the liveness of the gRPC server
Started to watch alerts
== Alert / 2026-05-25 04:10:46.438069 ==
ClusterName: default
HostName: aryan
NamespaceName: multiubuntu
PodName: quota-test-deployment-5bc54c58b9-4rpvw
Labels: app=quota-test-pod
Type: MatchedNetworkPolicy
PolicyName: quota-test-policy
Resource: EGRESS
Operation: NetworkFirewall
Action: Block
Data: SourceIP=10.42.0.233 SourcePort=0 DestinationIP=8.8.8.8 DestinationPort=0 Protocol=ICMP QuotaLevel=policy QuotaLimit=2MB
EventData: map[DestinationIP:8.8.8.8 DestinationPort:0 Protocol:ICMP QuotaLevel:policy QuotaLimit:2MB SourceIP:10.42.0.233 SourcePort=0]
Enforcer: NetworkPolicyEnforcer
Result: Permission denied
ExecEvent: map[]
PPID: 0
UID: 0
```

</details>

<br>

<details>
<summary><b>3. Host-Level Quota Policy (Global Node Limits)</b></summary>

*   **Identification**: Automatically detected if the policy defines a `nodeSelector` (targeting standard host-level/global rules on the Node itself) rather than a pod `selector`.
*   **Behavior**: Applies bandwidth limits globally to the host node. Since it operates directly in the host namespace, it does not use or reference container-specific levels (no `QuotaLevel=pod` or `QuotaLevel=policy` is printed or logged).
*   **Use Case**: Prevent host nodes from exceeding a specific data transfer threshold for audit or rate-limiting purposes.

**Host Policy Example:**
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorNetworkPolicy
metadata:
  name: host-egress-quota
spec:
  nodeSelector:
    matchLabels:
      kubernetes.io/hostname: aryan
  action: Audit
  egress:
  - limit: "4MB"
    duration: "20m"
```

**Corresponding Telemetry Alert Log:**
When the 4MB limit is crossed on the host, KubeArmor generates a telemetry alert showing only the **`QuotaLimit=4MB`** (with no pod or policy levels, as host policies are node-wide):

```text
== Alert / 2026-05-25 04:50:02.614033 ==
ClusterName: default
HostName: aryan
Type: MatchedNetworkPolicy
PolicyName: host-egress-quota
Resource: EGRESS
Operation: NetworkFirewall
Action: Audit
Data: SourceIP=192.168.1.16 SourcePort=0 DestinationIP=8.8.8.8 DestinationPort=0 Protocol=ICMP QuotaLimit=4MB
EventData: map[DestinationIP:8.8.8.8 DestinationPort:0 Protocol:ICMP QuotaLimit:4MB SourceIP:192.168.1.16 SourcePort=0]
Enforcer: NetworkPolicyEnforcer
Result: Passed
ExecEvent: map[]
NodeID: bf0fb10be96545e39587e5d7ad0c7aae
PPID: 0
UID: 0
```

**Under-the-Hood generated nftables rule at Host Level:**
When this host-level policy is applied, KubeArmor automatically generates and installs raw kernel-enforced `nftables` rules directly inside the host node's default network chains. It creates a named quota in the global `inet` table and hooks the action inside the host `OUTPUT` filter chain:

```nftables
# 1. Global Named Quota addition inside inet table
add quota inet kubearmor quota_host_egress_quota_Egress_0 { over 4 mbytes }

# 2. Host-Level Egress Audit & Log rules inside ip table OUTPUT chain
table ip kubearmor {
    chain OUTPUT {
        oifname "lo" accept
        ct state { established, related } accept
        quota name "quota_host_egress_quota_Egress_0" log prefix "host-egress-quota Egress Audit 4MB" group 0 accept
        accept
    }
}
```
*(Notice that there are no container IPs or namespace definitions; the rule intercepts traffic directly on the host's physical network adapters in the node's namespace!)*

</details>

---

## 🛡️ Policy Actions: Block vs Audit

KubeArmor supports two different security actions when a network quota threshold is crossed:

### 1. `action: Block`
If `action` is set to `Block`, KubeArmor dynamically sets up the rules to drop all subsequent packets matching the rule once the bandwidth limit is exceeded. 
*   **Behavior**: Traffic is actively blocked and rejected.
*   **Reset**: Access is restored automatically when the userspace timer resets the named quota at the end of the duration window.

### 2. `action: Audit` (Passive Logging / Alerts)
If `action` is set to `Audit`, KubeArmor enables a highly requested passive threshold monitoring pattern: **it sends an alert log when the limit is breached, but it does NOT block or drop the traffic.**
*   **Behavior**: Traffic continues to flow completely unrestricted.
*   **Log Suppression**: KubeArmor's Quota Silencer suppresses log flood; you get exactly **one alert** per pod/policy at the moment of the initial threshold breach. The silencer resets at the end of the duration window.

---

> 🛡️ **Important Note:**
> Policies targeting **Containers** (defined by containing selector labels/identities) strictly support bandwidth quota rules (rules declaring both 'limit' and 'duration') only.
