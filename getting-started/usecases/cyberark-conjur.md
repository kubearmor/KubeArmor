# CybeArk Conjur Hardening

Conjur manages the secrets required by applications and other non-human identities to gain access to critical infrastructure, data, and other resources. Conjur secures this access by managing secrets with granular Role-Based Access Control (RBAC) and other security best practices and techniques.

 

**Attack points in Conjur:**

CyberArk Conjur when deployed in the Kubernetes cluster stores sensitive information in the volume mount points. In the conjure-oss pod, the Conjur-nginx container stores the sensitive information in the etc/ssl and etc/nginx volume mount points. Conjur-oss container has /conjure-server volume mount point where the sensitive information is stored. In the Conjur-Postgres pod the sensitive information and secrets are stored in the /var/lib/postgresql/data and /etc/certs Volume mount points.


<img src="./../../.gitbook/assets/conjur.png" width="784" class="center" alt="Attack points in Conjur">

So if any attacker who gets access to these Volume mount points through lateral movements might see this sensitive information and secrets. Also, they can do encryption of the data and ask for ransomware. We can prevent these types of attacks AccuKnox’s runtime security engine KubeArmor. With the help of KubeArmor policies we can protect the access to these volume mount points and deny such attacks.

## Protecting Conjur-OSS Container:

**Before Applying policy:**

Currently, any attacker who gets access into the Conjur-oss pod can access the sensitive information stored in the /opt/conjur-server.

```sh
@LAPTOP-9Q1ERBHE:~$ kubectl exec -it -n conjur conjur-conjur-oss-698fbf6cd5-kb62v -c conjur-oss -- bash
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server# ls
API_VERSION         Gemfile       SECURITY.md                              build_utils.sh         debify.sh           release
CHANGELOG.md        Gemfile.lock  STYLE.md                                 config                 distrib             secrets.yml
CODE_OF_CONDUCT.md  Jenkinsfile   UPGRADING.md                             config.ru              docker-compose.yml  spec
CONTRIBUTING.md     LICENSE.md    VERSION                                  conjur-project-config  engines             tmp
DEBIFY_IMAGE        NOTICES.txt   VERSION_APPLIANCE                        conjur_git_commit      gems
Dockerfile          Procfile      app                                      contrib                lib
Dockerfile.fpm      README.md     bin                                      cucumber               log
Dockerfile.test     README_CI.md  build-and-publish-internal-appliance.sh  cucumber.yml           public
Dockerfile.ubi      Rakefile      build.ps1                                db                     publish-images.sh
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server# cat secrets.yml
REDHAT_API_KEY: !var redhat/projects/conjur/api-key
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server#
```

**Policy:**

We can protect access to these volume mount points using the following policy:

```sh
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: conjur-oss
  namespace: conjur
spec:
  selector:
    matchLabels:
      kubearmor.io/container.name: '[conjur-oss]'
  action: Allow
  file:
    matchDirectories:
    - dir: /opt/conjur-server/
      recursive: true
      action: Block
    - dir: /opt/conjur-server/
      recursive: true
      fromSource:
      - path: /var/lib/ruby/bin/ruby
      - path: /usr/bin/bash
    - dir: /
      recursive: true
  process:
    matchDirectories:
    - dir: /
      recursive: true
  message: Conjur-oss policy
```
In the above policy we are only allowing

+ /var/lib/ruby/bin/ruby to access /opt/conjur-server/ volume Mount

+ All the other process will be denied access to /opt/conjur-server/

**Applying policy:** 

We can apply the above policy in the cluster using the following command: 

```sh
@LAPTOP-9Q1ERBHE:~/cyberark-conjure$ kubectl apply -f conjure-oss.yaml
kubearmorpolicy.security.kubearmor.com/conjur-oss created
```
**After Applying Policy:**

Now with the KubeArmor policy in place, any attacker who gets access to the container will not be able to access the Conjur-server volume mount point that has the secret files stored in it.

```sh
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server# ls
ls: cannot open directory '.': Permission denied
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server# cat secrets.yml
cat: secrets.yml: Permission denied
root@conjur-conjur-oss-698fbf6cd5-kb62v:/opt/conjur-server#
```
**Karmor logs:** 

```sh
== Alert / 2023-06-09 05:25:32.948986 ==
ClusterName: default
HostName: aks-agentpool-16128849-vmss000002
NamespaceName: conjur
PodName: conjur-conjur-oss-698fbf6cd5-kb62v
Labels: app=conjur-oss,app.kubernetes.io/component=service,app.kubernetes.io/name=conjur,chart=conjur-oss-2.0.6,heritage=Helm,release=conjur
ContainerName: conjur-oss
ContainerID: 510ccf0598e72176dc3f20db1a7da7ac0bfd8f4cff8a3ff874a17b282ed4b55e
ContainerImage: docker.io/cyberark/conjur:latest@sha256:9b2b30abea516c2b4f3e4d98dfd4c71289bbbb6b921c7ce22800d0e9c522cadb
Type: MatchedPolicy
PolicyName: DefaultPosture
Source: /usr/bin/cat secrets.yml
Resource: secrets.yml
Operation: File
Action: Block
Data: syscall=SYS_OPENAT fd=-100 flags=O_RDONLY
Enforcer: eBPF Monitor
Result: Permission denied
HostPID: 1.381947e+06
HostPPID: 1.380415e+06
PID: 103
PPID: 88
ParentProcessName: /usr/bin/bash
ProcessName: /usr/bin/cat
```
## Protecting Conjur-Nginx:

**Before Applying policy:**

In the Conjur pod, if any attacker who gets access to the Conjur-nginx container can access the etc/nginx volume mount point

```sh
@LAPTOP-9Q1ERBHE:~$ kubectl exec -it -n conjur conjur-conjur-oss-698fbf6cd5-kb62v -c conjur-nginx -- bash
root@conjur-conjur-oss-698fbf6cd5-kb62v:/# cd etc/nginx
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx# ls
dhparams.pem  mime.types  nginx.conf  sites-enabled
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx# cat dhparams.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAhg2rRNwhgO8Nxc363bnKNKxb7xP8BXdQBnEHNxtqfpPRQViiP8K9
fMHHvN5/QAeB0hCOEg6dhbYurOcT9ZfFy9BSC9QFTixfDmMHe9MT1VIYqvsXVyjO
l/ivdCW0/eMZ5sc1Fcleym+TQzzrgnI0Kad17tmq4tvBKky+0YY4Q/M9BupZ7omc
fyqhY+LyEqIjWuCd3eE7YQIonOrXJ+8xuOjl5uilFu4Zz+i4KeELmAG1WaOjvg+Z
dJcve9soB3uaJW45jS/7cRl94VPJsfCJC/Z6E2R6CSPDgvytxL8aAM5FCyMQljN3
vS9xNgsWz5gZqU3gbxW2dRgedjEvW5VHMwIBAg==
-----END DH PARAMETERS-----
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx#
```

**Policy:**

We can protect access to these volume mount points using the following policy:

```sh
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: conjur-nginx
  namespace: conjur
spec:
  selector:
    matchLabels:
      kubearmor.io/container.name: '[conjur-nginx]'
  action: Allow
  file:
    matchDirectories:
    - dir: /etc/nginx/
      recursive: true
      action: Block
    - dir: /etc/nginx/
      recursive: true
      fromSource:
      - path: /usr/sbin/nginx
    - dir: /opt/conjur/etc/ssl/
      recursive: true
      action: Block
    - dir: /opt/conjur/etc/ssl/
      recursive: true
      fromSource:
      - path: /usr/sbin/nginx
    - dir: /
      recursive: true
  process:
    matchDirectories:
    - dir: /
      recursive: true
  message: Conjur-nginx-policy
```
In the above policy, we are only allowing

+ /usr/sbin/nginx to access /opt/conjur/etc/ssl and /etc/nginx volume Mount points

+ All the other processes will be denied access to /opt/conjur/etc/ssl and /etc/nginx volume Mount points

**Applying Policy:** 

We can apply the above policy in the cluster using the following command: 

```sh
@LAPTOP-9Q1ERBHE:~/cyberark-conjure$ kubectl apply -f conjure-nginx.yaml
kubearmorpolicy.security.kubearmor.com/conjur-nginx created
```
**After Applying Policy:**

With the kubeArmor policy applied, access to the Volume mount etc/nginx will be denied. The attacker will not be able to access the secrets stored in these Volume mount points.

```sh
@LAPTOP-9Q1ERBHE:~$ kubectl exec -it -n conjur conjur-conjur-oss-698fbf6cd5-kb62v -c conjur-nginx -- bash
root@conjur-conjur-oss-698fbf6cd5-kb62v:/# cd etc/nginx
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx# ls
ls: cannot open directory '.': Permission denied
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx# cat dhparams.pem
cat: dhparams.pem: Permission denied
root@conjur-conjur-oss-698fbf6cd5-kb62v:/etc/nginx#
```

**Karmor logs:** 

```sh
== Alert / 2023-06-09 05:29:46.288084 ==
ClusterName: default
HostName: aks-agentpool-16128849-vmss000002
NamespaceName: conjur
PodName: conjur-conjur-oss-698fbf6cd5-kb62v
Labels: release=conjur,app=conjur-oss,app.kubernetes.io/component=service,app.kubernetes.io/name=conjur,chart=conjur-oss-2.0.6,heritage=Helm
ContainerName: conjur-nginx
ContainerID: 6c1a332c38c8d63f2bbdda993f7c9c30d1f20a28a4c7f7186f98ff3da3a79564
ContainerImage: docker.io/library/nginx:1.15@sha256:23b4dcdf0d34d4a129755fc6f52e1c6e23bb34ea011b315d87e193033bcd1b68
Type: MatchedPolicy
PolicyName: DefaultPosture
Source: /bin/cat dhparams.pem
Resource: dhparams.pem
Operation: File
Action: Block
Data: syscall=SYS_OPEN flags=O_RDONLY
Enforcer: eBPF Monitor
Result: Permission denied
HostPID: 1.387755e+06
HostPPID: 1.387015e+06
PID: 85
PPID: 79
ParentProcessName: /bin/bash
ProcessName: /bin/cat
```
## Protecting Conjur-Postgres:

**Before Applying Policy:**

In the Conjur-postgres pod, if an attacker gets access to the container can access the Volume mount points /etc/certs and /var/lib/postgresql/data which contains the sensitive data.

```sh
@LAPTOP-9Q1ERBHE:~$ kubectl exec -it -n conjur conjur-postgres-0 -- bash
root@conjur-postgres-0:/# ls
bin   dev                         docker-entrypoint.sh  home  lib64  mnt  proc  run   srv  tmp  var
boot  docker-entrypoint-initdb.d  etc                   lib   media  opt  root  sbin  sys  usr
root@conjur-postgres-0:/# cd etc/certs
root@conjur-postgres-0:/etc/certs# ls
tls.crt  tls.key
root@conjur-postgres-0:/etc/certs# cat tls.key
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2hzzMQoSqxq5lDlLnuO7Bhj22qJptRFnJF2VSxISW9MBrInf
eaE9hYEpPQdcWCPI6m8qG30UnQg2NhIymEzMNwZoK200vRG8tE95IFTZ1woot+O2
5RfCdX+X8ERFiGCWD6pDrbx5eO/QHLrU1lLng4wmRoJjWlS1KuD7NKRX7wXKOmEN
duqZJX2uSzw1jgBJH522TiHfo2pzoZz39GUoV22qri7WD+/3YSJBIlZ/Ts7dc7gJ
TD993l5LkIGQ7okuffM8i40Ph3/u50jabNuMaKtaRe+BQA8kJUGlGV6O+WoSc7uv
liL10njXfXeIdlNYrdOwjPZ/Jwr8fj2z594wIwIDAQABAoIBAQCEkjgWxIKYUYQe
3bxi9RRGHoJcXX9WuR8x8Ve+61sRSO2pi5uzeBfGv7zrBUBRql6Cb9LuJlaTI9yf
fOwXugYeI9zJGHWHvfIuvmdnCWvm0pvxOY1/LbPaaxVUyopg3CQZnWnJfddvdIPQ
EpcvNfDV+ieBj9sHmpkLWPgXBRUViBYDojwDdPcAu9XnWEvfDuzEEmNKFwRTSz+r
rQF9RBxZYzRT93p9I/XNhWH08J4NsWbZuc7+qyEiT7a5qdXKMAqo0ZXyHt7k2XKJ
sLplafZDzc+iMkani5J/ClDeFddZhlQ7oFsyjtOakDlzxOwBGFr48EBGP3llSIld
Q5GtQgEBAoGBAPNs6vnv/D2dkMcJgiH09mQFxzb0SvATYYsZ3dj0AUYkU84akVMt
eQT5WTHY8jAkFk1MgsWlPqIwy7Ty2Z8K54efZr8hQW2D6/W2g57xDMfKQOWBmArk
F/1r1eVOZTdBIcJgDNuc0i0JppfRABAZl+M5rysIGQiP9zL5RlvO16hjAoGBAOVh
THwxnf7Y8o4CJyexFQbsrTq/5KXLmZRPKWxw78Tb0R0RMZQuZjf4lWE5g6b0BUf8
vIPtyTEKaCcd+u34AU0LbltUfa1gzRWxIO1zOCeXTrWZYujBUATdWoa7+4FyJNOH
PlfX4kUu2iqRjKQdahV4LwCI/hzu55ST6JuwK4VBAoGBAIGgR4SvAiCBjn4fFxgk
DSz4Urx13I35lCDxtkx4q1EBuUrwpOCpP1+htJix0U5HeUTScHT1aOQPnfqOs8pY
kTCMdrdi6yd5b6aZ+X8jF84watyMZT2vdwLxcKa6V3XUDjkm0tIDsXxgPkFr/1+T
cWmD5z7AAiyoFVgknA35mKfHAoGBALxm55CWnGQHQ2qaoBh83X17hmlb1ezLxxBG
2QpF1NpHhoGubp98YN8WIXPi7pyBj5jqINjnxTmvh46hlEpDSqZCflkrk7KFcM2h
WB9QZM43/CEypEfzB8uHGGTUICbZXyAS1IUIP8R9UBpoxDDELC8IMOrqmnWfULz7
o7HEyGpBAoGAU8y+BARyNA8KCbbWBCNjWQZFMw3u3RePbjQKiQwLurq/oGF57wPp
uO9+ZwQhb6KDuL6pgytoxA28gvkWMOdcQUzs4ExMbkZbPbyvHECgtd3aL8gAsebt
mT36DmCECP3zVYhO00PYBs+ImlGPgZpy3GoNkaPjy5noTEFLtJ7S5K4=
-----END RSA PRIVATE KEY-----
root@conjur-postgres-0:/etc/certs#
```
**Policy:**

We can protect access to these volume mount points using the following policy:

```sh
apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: conjur-postgres
  namespace: conjur
spec:
  selector:
    matchLabels:
      app: conjur-oss-postgres
  action: Allow
  file:
    matchDirectories:
    - dir: /etc/certs/
      recursive: true
      action: Block
    - dir: /etc/certs/
      recursive: true
      fromSource:
      - path: /usr/lib/postgresql/10/bin/postgres
    - dir: /var/lib/postgresql/data/
      recursive: true
      action: Block
    - dir: /var/lib/postgresql/data/
      recursive: true
      fromSource:
      - path: /usr/lib/postgresql/10/bin/postgres
    - dir: /
      recursive: true
  process:
    matchDirectories:
    - dir: /
      recursive: true
    matchPaths:
    - path: /bin/su
      action: Block
    - path: /usr/lib/postgresql/10/bin/psql
      action: Block
  message: Conjur-Postgres-policy
```
In the above policy, we are only allowing

+ /usr/lib/postgresql/10/bin/postgres to access /var/lib/postgresql/data/ and /etc/certs/ volume Mount points

+ All the other processes will be denied access to /var/lib/postgresql/data/ and /etc/certs/ volume Mount points

**Applying Policy:**

We can apply the above policy in the cluster using the following command: 

```sh
@LAPTOP-9Q1ERBHE:~/cyberark-conjure$ kubectl apply -f conjure-postgres.yaml
kubearmorpolicy.security.kubearmor.com/conjur-postgres created
```
**After Applying Policy:**

```sh
@LAPTOP-9Q1ERBHE:~$ kubectl exec -it -n conjur conjur-postgres-0 -- bash
root@conjur-postgres-0:/# ls
bin   dev                         docker-entrypoint.sh  home  lib64  mnt  proc  run   srv  tmp  var
boot  docker-entrypoint-initdb.d  etc                   lib   media  opt  root  sbin  sys  usr
root@conjur-postgres-0:/# cd etc/certs
root@conjur-postgres-0:/etc/certs# ls
ls: cannot open directory '.': Permission denied
root@conjur-postgres-0:/etc/certs# cat tls.key
cat: tls.key: Permission denied
root@conjur-postgres-0:/etc/certs#
```

**Karmor logs:**

```sh
== Alert / 2023-06-09 05:40:06.221013 ==
ClusterName: default
HostName: aks-agentpool-16128849-vmss000001
NamespaceName: conjur
PodName: conjur-postgres-0
Labels: app.kubernetes.io/name=conjur,chart=conjur-oss-2.0.6,heritage=Helm,release=conjur,statefulset.kubernetes.io/pod-name=conjur-postgres-0,app=conjur-oss-postgres,app.kubernetes.io/component=postgres
ContainerName: postgres
ContainerID: c36e07814c4057075197807578719bf016917cc0b302b300d4c9b051cd7e7014
ContainerImage: docker.io/library/postgres:10.16@sha256:04651ba891b13220fa062bcd17bba8b9780168396da535a04ed6712855c545f8
Type: MatchedPolicy
PolicyName: DefaultPosture
Source: /bin/cat tls.key
Resource: tls.key
Operation: File
Action: Block
Data: syscall=SYS_OPEN flags=O_RDONLY
Enforcer: eBPF Monitor
Result: Permission denied
HostPID: 2.707104e+06
HostPPID: 2.696545e+06
PID: 3543
PPID: 3534
ParentProcessName: /bin/bash
ProcessName: /bin/cat
```