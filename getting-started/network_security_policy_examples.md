# Examples of Network Security Policy

Here, we demonstrate how to define network security policies.

* DNS lookup restriction
  * Block outgoing DNS traffic \([nsp-egress-block-dns.yaml](../examples/network-security-policies/nsp-egress-block-dns.yaml)\)

    ```text
    apiVersion: security.kubearmor.com/v1
    kind: KubeArmorNetworkPolicy
    metadata:
      name: nsp-egress-block-dns
    spec:
      nodeSelector:
        matchLabels:
          kubernetes.io/hostname: "kubearmor-dev"
      egress:
      - to:
        - ipBlock:
            cidr: "8.8.8.8/32"
        ports:
        - port: "dns"
          protocol: "UDP"
      severity: 5
      action: Block
    ```

    * Explanation: The purpose of this policy is to audit the outgoing DNS packets (UDP) to 8.8.8.8 in a host whose host name is 'kubearmor-dev'. For this, we define 'kubernetes.io/hostname: kubearmor-dev' in nodeSelector -&gt; matchLabels and the specific address \('8.8.8.8'\) in egress -&gt; to  and port + protocol ('dns' and 'UDP') egress -&gt; ports. Also, we put 'Block' as the action of this policy.

    * Verification: After applying this policy, please open a new terminal (or connect to the host with a new session) and run `nc -uvz -w 2 1.1.1.1 53`. You will see that it runs without an output and an alert is generated.

    ---
    **NOTE**

    The given policy works with almost every linux distribution. If it is not working in your case, check if nftables is enabled on your system.

    ---

* Ingress alerting
  * Alert for incoming SSH connections
  ```text
  apiVersion: security.kubearmor.com/v1
  kind: KubeArmorNetworkPolicy
  metadata:
    name: nsp-ingress-audit-ssh
  spec:
    nodeSelector:
      matchLabels:
        kubearmor.io/hostname: "ubuntu"
    ingress:
    - from:
      - ipBlock:
          cidr: "192.168.29.0/24"
      ports:
      - port: "ssh"
    message: "New SSH connection!"
    severity: 5
    action: Audit
  ```

  <details>
  <summary>Generated telemetry</summary>

  ```json
  {
    "Timestamp": 1771821095,
    "UpdatedTime": "2026-02-23T04:31:35.104233Z",
    "ClusterName": "default",
    "HostName": "ubuntu",
    "PPID": 0,
    "UID": 0,
    "PolicyName": "nsp-ingress-audit-ssh",
    "Severity": "5",
    "Message": "New SSH connection!",
    "Type": "MatchedNetworkPolicy",
    "Operation": "NetworkFirewall",
    "Resource": "INGRESS",
    "Data": "SourceIP=192.168.29.42 SourcePort=53262 DestinationIP=192.168.29.76 DestinationPort=22 Protocol=TCP",
    "EventData": {
      "DestinationIP": "192.168.29.76",
      "DestinationPort": "22",
      "Protocol": "TCP",
      "SourceIP": "192.168.29.42",
      "SourcePort": "53262"
    },
    "Enforcer": "NetworkPolicyEnforcer",
    "Action": "Audit",
    "Result": "Passed",
    "ExecEvent": {},
    "NodeID": "f39801455594d78b98b7816e37eed6e526c2342d945ba334f6ab6086b49426ee",
    "UserName": "root"
  }
  ```
  </details>