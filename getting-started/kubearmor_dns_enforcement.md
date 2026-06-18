# KubeArmor DNS Enforcement Guide

KubeArmor supports kernel-native DNS firewalling using **BPF LSM**. By specifying `matchDNSQueries` rules inside a `KubeArmorPolicy`, you can restrict or audit pod DNS resolutions to domain names.

---

## 1. Supported Actions

KubeArmor DNS policy rules support the standard three policy actions: **Block**, **Audit**, and **Allow**.

| Action | Behavior | Primary Use Case |
| :--- | :--- | :--- |
| **`Block`** | Instantly drops the matching DNS query at the kernel level. The calling process receives a "Permission Denied"| Active blocking of malicious/unapproved domains. |
| **`Audit`** | Allows the DNS query to pass through normally but records a matching telemetry audit log. | Monitoring network connections or testing policies before enforcing them. |
| **`Allow`** | Explicitly permits the matching DNS query. Any domain *not* covered by an allow rule can be blocked using a default posture. | White-listing specific internal or API domains while blocking all others. |

---

## 2. Defining Policies

### Example A: Blocking DNS Queries (Active Enforcement)
Below is an example of a `KubeArmorPolicy` that actively blocks DNS lookup requests for `google.com` (and its subdomains).

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: block-dns-query-to-google
  namespace: multiubuntu
spec:
  severity: 10
  selector:
    matchLabels:
      container: ubuntu-1
  network:
    matchDNSQueries:
    - domain: google.com
  action: Block
```

---

## 3. Verification & Enforcement in Action


If a blocked domain is requested, the DNS lookup is dropped, and `curl` fails with a resolution error:

```bash
# Exec into your target pod
kubectl exec -it -n multiubuntu ubuntu-1-deployment-748575cfcc-5bdpq -- bash

# Attempt to resolve the blocked domain
curl google.com
```

**Expected output (Block):**
```text
curl: (6) Could not resolve host: google.com
```

---

## 4. Alert Telemetry

 Below is the detailed JSON representation of the resulting alert:

```json
{
  "Timestamp": 1779770817,
  "UpdatedTime": "2026-05-26T04:46:57.355927Z",
  "ClusterName": "default",
  "HostName": "aryan",
  "NamespaceName": "multiubuntu",
  "Owner": {
    "Ref": "Deployment",
    "Name": "ubuntu-1-deployment",
    "Namespace": "multiubuntu"
  },
  "PodName": "ubuntu-1-deployment-748575cfcc-5bdpq",
  "Labels": "container=ubuntu-1,group=group-1",
  "ContainerID": "d703a51bf1c125e1fe74652e92e961a10d2358e387c37e7c45a1ca00fc951c00",
  "ContainerName": "ubuntu-1-container",
  "HostPID": 781163,
  "PID": 114,
  "UID": 0,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/usr/bin/curl",
  "PolicyName": "block-dns-query-to-google-subdomains",
  "Severity": "10",
  "Type": "MatchedPolicy",
  "Source": "/usr/bin/curl google.com",
  "Operation": "Network",
  "Resource": "google.com",
  "Data": "lsm=SOCKET_SENDMSG domain=google.com.multiubuntu.svc.cluster.local",
  "EventData": {
    "Domain": "google.com.multiubuntu.svc.cluster.local",
    "Lsm": "SOCKET_SENDMSG"
  },
  "Enforcer": "BPFLSM",
  "Action": "Block",
  "Result": "Permission denied"
}
```