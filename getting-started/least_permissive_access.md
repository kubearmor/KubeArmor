# Least Permissive Access (enforcing Zero Trust Posture)

Zero trust is a security concept that involves verifying the identity and trustworthiness of users and devices before granting them access to resources, rather than assuming that all users and devices within a network are trusted. In a zero trust posture, access to resources is strictly controlled and constantly evaluated, and any deviations from the expected behavior are immediately detected and addressed.

KubeArmor is a tool that helps organizations enforce a zero trust posture within their Kubernetes clusters. It allows users to define an allow-based policy that specifies the specific system behavior that is allowed, and denies or audits all other behavior. This helps to ensure that only authorized activities are allowed within the cluster, and that any deviations from the expected behavior are flagged for further investigation.

By implementing a zero trust posture with KubeArmor, organizations can increase their security posture and reduce the risk of unauthorized access or activity within their Kubernetes clusters. This can help to protect sensitive data, prevent system breaches, and maintain the integrity of the cluster.

KubeArmor supports allow-based policies which results in specific actions to be allowed and denying/auditing everything else. For example, a specific pod/container might only invoke a set of binaries at runtime. As part of allow-based rules you can specify the set of processes that are allowed and everything else is either audited or denied based on the [default security posture](default_posture.md).

<img src="../.gitbook/assets/zero-trust.png" width="512" class="center" alt="KubeArmor enforcing Zero Trust Posture">

## Sample use-cases for allow based policies

### Allow execution of only specific processes within the pod

The sample [DVWA application](https://github.com/cytopia/docker-dvwa) has two deployments (dvwa-sql and dvwa-web). DVWA web application by default executes only `/usr/sbin/apache2` and `/usr/bin/ping`. The following policy would restrict execution of unknown processes (i.e, allow only specific processes and deny everything else):

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: allow-specific-process
  namespace: dvwa
spec:
  action: Allow
  file:
    matchDirectories:
    - dir: /
      recursive: true
  process:
    matchPaths:
    - path: /bin/bash
    - fromSource:
      - path: /bin/dash
      path: /bin/ping
    - fromSource:
      - path: /usr/sbin/apache2
      path: /bin/sh
    - path: /usr/sbin/apache2
  selector: 
    matchLabels:
      app: dvwa-web
      tier: frontend
  severity: 1
```

## Challenges with maintaining Zero Trust Security Posture

Achieving Zero Trust Security Posture is difficult. However, the more difficult part is to maintain the Zero Trust posture across application updates. There is also a risk of application downtime if the security posture is not correctly identified. While KubeArmor provides a way to enforce Zero Trust Security Posture, identifying the policies/rules for achieving this is handled by [Discovery Engine](https://github.com/kubearmor/discovery-engine/).

KubeArmor additionally provides tooling, gaurdrails so as to smoothen the journey to Zero Trust posture. For e.g., it is possible to set dry-run/audit mode at the namespace level by [configuring security posture](default-posture.md). Thus, you can have different namespaces in different default security posture modes (default-deny vs default-audit). Users can switch to default-deny mode once they are comfortable (i.e., they do not see any alerts) with the settings.
