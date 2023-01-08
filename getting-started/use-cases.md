# Use-cases

<details>
  <summary><h2>Block access to k8s service account token</h2></summary>

### Description
K8s mounts the service account token as part of every pod by default. The service account token is a credential that can be used as bearer token to access k8s APIs and gain access to other k8s entities. Many a times there are no processes in the pod that use service account token which means in such cases the k8s service account token is an unused asset that can be leveraged by the attacker.

### Attack Scenario
An attacker would check for credential accesses so as to do lateral movements. For e.g., in most k8s attacks, the attacker after gaining entry into the k8s pods tries to use service account token and gain access into other entities.
  
### Sample Policy
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-wordpress-block-sa
  namespace: wordpress-mysql
spec:
  severity: 7
  selector:
    matchLabels:
      app: wordpress
  file:
    matchDirectories:
    - dir: /run/secrets/kubernetes.io/serviceaccount/
      recursive: true

      # cat /run/secrets/kubernetes.io/serviceaccount/token
      # curl https://$KUBERNETES_PORT_443_TCP_ADDR/api --insecure --header "Authorization: Bearer $(cat /run/secrets/kubernetes.io/serviceaccount/token)"

  action:
    Block
```
[Wordpress-MySQL example reference](../examples/wordpress-mysql/)
</details>

<details>
  <summary><h2>File Integrity Monitoring (FIM)</h2></summary>

### Description
Changes to system binary folders, configuration paths, credentials paths needs to be monitored for change. With KubeArmor, one can not only monitor for changes but also block any write attempts in such system folders. Compliance frameworks such as PCI-DSS, SOX, NERC CIP, FISMA, HIPAA, SANS expect FIM to be in place.

### Attack Scenario
An attacker might want to update the configuration so as to disable security controls or access logs.
 
### Sample Policy
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: fim-for-system-paths
  namespace: dvwa
spec:
  action: Block
  file:
    matchDirectories:
    - dir: /bin/
      readOnly: true
      recursive: true
    - dir: /sbin/
      readOnly: true
      recursive: true
    - dir: /usr/sbin/
      readOnly: true
      recursive: true
    - dir: /usr/bin/
      readOnly: true
      recursive: true
  message: Alert! An attempt to write to system directories denied.
  severity: 5
  tags:
  - NIST
  - PCI-DSS
```
</details>

<details>
  <summary><h2>Deny updates to root certs or trust bundles</h2></summary>

### Description
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system.

### Attack Scenario
Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials.
 
### Sample Policy
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: protect-trust-bundles
  namespace: dvwa
spec:
  action: Block
  file:
    matchDirectories:
    - dir: /etc/ssl/
      readOnly: true
      recursive: true
    - dir: /etc/pki/
      readOnly: true
      recursive: true
    - dir: /usr/local/share/ca-certificates/
      readOnly: true
      recursive: true
  message: Credentials modification denied
  severity: 1
  tags:
  - MITRE
  - MITRE_T1552_unsecured_credentials
```
</details>

<details>
  <summary><h2>Process Whitelisting</h2></summary>

### Description
You can use a security feature called "process isolation" or "process whitelisting" to set specific processes to be executed as part of a container or pod, and deny everything else. This can help to secure a containerized environment by limiting the processes that can run within it, and preventing unauthorized processes from being executed.

### Attack Scenario
Attacker uses command injection techniques to insert binaries in the pods/workloads and then execute the binary. Process-Whitelisting will deny any unknown process from execution.
  
### Sample Policy
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
This policy allows `apache2`, `ping` and few shell accesses in the pod and denies everything else.
</details>

<details>
  <summary><h2>Deny execution of specific binaries in the pod</h2></summary>

### Description
Pods/Containers might get shipped with binaries which should never used in the production environments. Some of those bins might be useful in dev/staging environments but the same container image is carried forward in most cases to the production environment too. For security reasons, the devsecops team might want to disable use of these binaries in the production env even though the bins exists in the container. As an example, most of the container images are shipped with package management tools such as `apk`, `apt`, `yum`, etc. If anyone ends up using these bins in the prod env, it will increase the attack surface of the container/pod.

### Attack Scenario
Attackers use system tools such `fsck`, `ip`, `who`, `apt` etc for reconnaissance and to download its accessory tooling from the remote servers.
  
### Sample Policy

This policy denies execution of package management tools such as `apt`, `apt-get` in the target pods.
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-wordpress-block-process
  namespace: wordpress-mysql
spec:
  severity: 3
  selector:
    matchLabels:
      app: wordpress
  process:
    matchPaths:
    - path: /usr/bin/apt
    - path: /usr/bin/apt-get
  action:
    Block
```
</details>

<details>
  <summary><h2>Limit access to raw database tables in the pod</h2></summary>

### Description
MySQL and other database systems keep their raw tables in a specific folder path. This path can either if a path in a volume mount or local to the pod. Typically, these raw tables are accessed only by certain set of processes such as `mysqld`, `mysqldump`, `mysqladmin`. Any other binary should never be allowed to read or write into this folder.

### Attack Scenario
Attackers will try to:
1. exfiltrate the raw tables to obtain user and other information
2. encrypt the contents of the files associated with tables for ransomware purpose
3. delete the tables to cause system downtime
  
### Sample Policy
TODO
</details>

<details>
  <summary><h2>Allow only specific processes to use network primitives</h2></summary>

### Description
Typically, within a pod/container there are only specific processes that need to use network access. KubeArmor allows one to specify the set of binaries that are allowed to use network primitives such as TCP, UDP, Raw sockets and deny everyone else.

### Attack Scenario
An attacker binary would try to send a beacon to its C&C (Command and Control) Server. Also the binary might use the network primitives to exfiltrate pod/container data/configuration.
  
### Sample Policy
TODO
</details>

## Generic use-cases
- Restrict the behavior of containers and nodes (VMs) at the system level

  Traditional container security solutions protect containers by determining their inter-container relations \(i.e., service flows\) at the network level. In contrast, KubeArmor prevents malicious or unknown behaviors in containers by specifying their desired actions \(e.g., a specific process should only be allowed to access a sensitive file\). KubeArmor also allows operators to restrict the behaviors of nodes (VMs) based on node identities.

- Enforce security policies to containers and nodes (VMs) at runtime

  In general, security policies \(e.g., Seccomp and AppArmor profiles\) are statically defined within pod definitions for Kubernetes, and they are applied to containers at creation time. Then, the security policies are not allowed to be updated in runtime.

  To address those problems, KubeArmor users k8s CRDs to define security policies, such that the orchestration of the policy is handled by the k8s control plane. KubeArmor leverages Linux Security Modules (LSMs) to enforce the security policies at the container level according to the labels of given containers and security policies. Similiarly, KubeArmor support policy enforcement at the Host/Node/VM level using `KubeArmorHostSecurityPolicy` k8s resource.

- Produce container-aware alerts and system logs

  LSMs do not have any container-related information; thus, they generate alerts and system logs only based on system metadata \(e.g., User ID, Group ID, and process ID\). It is hard to figure out what containers cause policy violations. KubeArmor uses an eBPF-based system monitor to keep track of process life cycles in containers and even nodes, and converts system metadata to container/node identities when LSMs generate alerts and system logs for any policy violations from containers and nodes (VMs).

- Provide easy-to-use semantics for policy definitions

  KubeArmor provides the ability to monitor the life cycles of containers' processes and take policy decisions based on them. In general, it is much easier to deny a specific action, but it is more difficult to allow only specific actions while denying all. KubeArmor manages internal complexities associated with handling such policy decisions and provides easy semantics towards policy language.

- Support network security enforcement among containers

  KubeArmor aims to protect containers and nodes (VMs) themselves rather than inter-container/inter-node communications. However, using KubeArmor a user can add policies that could apply policy settings at the level of network system calls \(e.g., bind\(\), listen\(\), accept\(\), and connect\(\)\), thus controlling interactions among containers and nodes (VMs).

