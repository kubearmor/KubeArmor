## Monitoring Network Quotas with KubeArmor

KubeArmor's network monitoring feature allows you to track network bandwidth usage against predefined quotas over a specific time period. You can create policies to audit (generate alerts) when a host exceeds a certain amount of data transfer (e.g., 2MB) within a set duration (e.g., 120 seconds).

This feature is useful for:

* Identifying anomalous network activity, such as unexpected large data transfers.

* Auditing bandwidth-heavy workloads on specific nodes.

* Observing network usage patterns for capacity planning.

### Limitations and Prerequisites

#### Please be aware of the following limitations before enabling this feature:

* Policy Type: This feature currently only supports Audit actions.

* Policy Level: This feature is only available for KubeArmorHostPolicy (node-level policies).

* At any given time, only one network limit policy can be active per node. Applying a new policy will overwrite the previous one.

>Note This feature is currently available only for Linux kernels version 5.x and above. This is due to eBPF verifier limitations and is planned to be addressed in future releases. 

### Enabling Network monitoring

This feature can be enabled using `--enableNetworkLimit` flag in kubearmorconfig 

### Disabling Network limit 
To disable the feature, you can either set the flag to false or remove it entirely from your kubeArmorconfig.

### Example

#### Policy Parameters
The `network` block in a **KubeArmorHostPolicy** supports the following parameters for quota monitoring:

| Parameter   | Description                                           | Supported Values |
|--------------|-------------------------------------------------------|------------------|
| `direction`  | The direction of traffic to monitor | `ingress`, `egress` |
| `limitSize`  | The data quota threshold. | Suffixes: `M` (Megabytes), `G` (Gigabytes)<br>Example: `"100M"`, `"2G"` |
| `duration`   | The rolling time window for the quota. | Suffixes: `s` (seconds), `m` (minutes), `h` (hours)<br>Example: `"30s"`, `"5m"`, `"1h"` |
| `limitCount`   | The rolling packets count window for the quota. | Number of packets <br>Example: `"1000000"`|

#### Sample policy 1
```yaml 
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: networklimit
spec:
  nodeSelector:
    matchLabels:
      kubernetes.io/hostname: aryan
  severity: 5
  network:
    ingress:
      limitSize: "2M"
      duration: "120s"
  action:
    Audit
```

#### Policy Explanation:
* This KubeArmorHostPolicy applies to the node named aryan.
It monitors ingress (incoming) network traffic.
If the total data received by this node exceeds 2 Megabytes within any 120-second (2-minute) rolling window, KubeArmor will generate an audit alert.

When the policy's conditions are met, KubeArmor will generate an alert log similar to the one below.
```json
  "Timestamp":1760554504,
  "UpdatedTime":"2025-10-15T18:55:04.287898Z",
  "ClusterName":"default",
  "HostName":"aryan",
  "PPID":0,
  "UID":0,
  "PolicyName":"networklimit",
  "Type":"MatchedHostPolicy",
  "Operation":"Network",
  "Data":"DIRECTION=INGRESS LIMIT_SIZE=2M",
  "Enforcer":"eBPF Monitor",
  "Action":"Audit",
  "Result":"Passed"
```
#### Sample policy 2
```yaml 
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: networklimit
spec:
  nodeSelector:
    matchLabels:
      kubernetes.io/hostname: aryan
  severity: 5
  network:
    ingress:
      limitSize: "2M"
      limitCount: "10000"
      duration: "120s"
  action:
    Audit
```
#### Policy Explanation:
* This KubeArmorHostPolicy applies to the node named aryan.
It monitors ingress (incoming) network traffic.
If, within any 120-second (2-minute) rolling window, the total ingress data received by the node exceeds 2 MB or the packet count surpasses 10,000, KubeArmor will trigger an audit alert.

When the policy's conditions are met, KubeArmor will generate an alert log similar to the one below.
```json
  "Timestamp":1760554704,
  "UpdatedTime":"2025-10-15T18:55:04.287898Z",
  "ClusterName":"default",
  "HostName":"aryan",
  "PPID":0,
  "UID":0,
  "PolicyName":"networklimit",
  "Type":"MatchedHostPolicy",
  "Operation":"Network",
  "Data":"DIRECTION=INGRESS LIMIT_SIZE=2M LIMIT_COUNT=10000",
  "Enforcer":"eBPF Monitor",
  "Action":"Audit",
  "Result":"Passed"






