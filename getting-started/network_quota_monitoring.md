## Monitor network quota using kubearmor 

KubeArmor comes with network montoring which helps you monitor network usage ove a period of time. This feature currently only support audit policies on host level. 

### Enabling Network monitoring

This feature can be enabled using --enableNetworkLimit flag in kubearmor config 

### Disabling Network limit 
This feature can be disabled by setting enableNetworkLimit flag to false or removing from the config

### Sample Policy 

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
This policy will generate alert like 

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





