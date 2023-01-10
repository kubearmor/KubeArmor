# Application Behavior/Summary

KubeArmor has visibility into systems and application behavior. KubeArmor summarizes/aggregates the information and provides a user-friendly view to figure out the application behavior.

<img src="../.gitbook/assets/app-behavior.png" width="400" class="center" alt="App Behavior">

## What application behavior is shown?

<img src="../.gitbook/assets/app-behavior2.png" width="784" class="center" alt="App Behavior2">

* *Process data*: 
	* What are the processes executing in the pods?
	* What processes are executing through which parent processes?
* *File data*: 
	* What are the file system accesses made by different processes?
* *Network Accesses*:
	* What are the Ingress/Egress connections from the pod?
	* What server binds are done in the pod?

## How to get the application behavior?

Pre-requisites:
1. Install KubeArmor
	* `curl -sfL http://get.kubearmor.io/ | sudo sh -s -- -b /usr/local/bin && karmor install`
2. Install [Discovery-engine](https://github.com/kubearmor/discovery-engine)
	* `kubectl apply -f https://raw.githubusercontent.com/kubearmor/discovery-engine/dev/deployments/k8s/deployment.yaml`
3. Next you install the workload. If the workload is already installed, then the behavior will be shown based on the new system events only.
4. Get the application summary
	* `karmor summary -n NAMESPACE`

# Sample Summary output

```
  Pod Name        dvwa-web-59b677c755-qmpkd   
  Namespace Name  dvwa                        
  Cluster Name    pandora-cluster             
  Container Name  dvwa                        
  Labels          app=dvwa-web,tier=frontend  

Process Data
+-----------------------------------------------------------------------------------------------------+--------------------------+-------+------------------------------+--------+
|                                             SRC PROCESS                                             | DESTINATION PROCESS PATH | COUNT |      LAST UPDATED TIME       | STATUS |
+-----------------------------------------------------------------------------------------------------+--------------------------+-------+------------------------------+--------+
| /bin/bash                                                                                           | /bin/ls                  | 2     | Wed Jan  4 12:35:38 UTC 2023 | Allow  |
| /bin/bash                                                                                           | /bin/rm                  | 1     | Wed Jan  4 13:54:37 UTC 2023 | Allow  |
| /bin/dash                                                                                           | /bin/cat                 | 1     | Thu Jan  1 00:00:00 UTC 1970 | Deny   |
| /bin/dash                                                                                           | /bin/ping                | 1     | Wed Jan  4 12:33:48 UTC 2023 | Allow  |
| /bin/dash                                                                                           | /bin/ping                | 3     | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /bin/dash                                                                                           | /usr/bin/head            | 2     | Thu Jan  1 00:00:00 UTC 1970 | Deny   |
| /bin/dash                                                                                           | /usr/bin/head            | 2     | Wed Jan  4 16:53:53 UTC 2023 | Allow  |
| /usr/sbin/apache2                                                                                   | /bin/sh                  | 1     | Wed Jan  4 12:33:48 UTC 2023 | Allow  |
| /usr/sbin/apache2                                                                                   | /bin/sh                  | 3     | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /var/lib/rancher/k3s/data/8307e9b398a0ee686ec38e18339d1464f75158a8b948b059b564246f4af3a0a6/bin/runc | /bin/bash                | 1     | Wed Jan  4 12:35:33 UTC 2023 | Allow  |
| /var/lib/rancher/k3s/data/8307e9b398a0ee686ec38e18339d1464f75158a8b948b059b564246f4af3a0a6/bin/runc | /bin/bash                | 1     | Wed Jan  4 13:54:20 UTC 2023 | Allow  |
+-----------------------------------------------------------------------------------------------------+--------------------------+-------+------------------------------+--------+


File Data
+-------------------+------------------------------+-------+------------------------------+--------+
|    SRC PROCESS    |    DESTINATION FILE PATH     | COUNT |      LAST UPDATED TIME       | STATUS |
+-------------------+------------------------------+-------+------------------------------+--------+
| /bin/bash         | /                            | 1     | Wed Jan  4 12:35:34 UTC 2023 | Allow  |
| /bin/bash         | /etc/                        | 10    | Wed Jan  4 13:54:30 UTC 2023 | Allow  |
| /bin/bash         | /lib/terminfo/x/xterm        | 1     | Wed Jan  4 12:35:33 UTC 2023 | Allow  |
| /bin/bash         | /lib/x86_64-linux-gnu/       | 3     | Wed Jan  4 13:54:20 UTC 2023 | Allow  |
| /bin/ls           | /etc/                        | 2     | Wed Jan  4 12:35:38 UTC 2023 | Allow  |
| /bin/ls           | /lib/x86_64-linux-gnu/       | 4     | Wed Jan  4 12:35:38 UTC 2023 | Allow  |
| /bin/ls           | /usr/lib/x86_64-linux-gnu/   | 1     | Wed Jan  4 12:35:38 UTC 2023 | Allow  |
| /bin/ping         | /etc/                        | 21    | Wed Jan  4 16:51:33 UTC 2023 | Allow  |
| /bin/ping         | /lib/x86_64-linux-gnu/       | 10    | Wed Jan  4 16:51:33 UTC 2023 | Allow  |
| /bin/ping         | /usr/lib/x86_64-linux-gnu/   | 7     | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /bin/rm           | /etc/                        | 2     | Wed Jan  4 13:54:37 UTC 2023 | Allow  |
| /bin/sh           | /etc/                        | 3     | Wed Jan  4 16:51:33 UTC 2023 | Allow  |
| /bin/sh           | /lib/x86_64-linux-gnu/       | 4     | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /usr/bin/head     | /etc/                        | 4     | Wed Jan  4 16:53:53 UTC 2023 | Allow  |
| /usr/bin/head     | /lib/x86_64-linux-gnu/       | 2     | Wed Jan  4 16:53:53 UTC 2023 | Allow  |
| /usr/sbin/apache2 | /etc/                        | 32    | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /usr/sbin/apache2 | /lib/x86_64-linux-gnu/       | 3     | Wed Jan  4 16:51:05 UTC 2023 | Allow  |
| /usr/sbin/apache2 | /proc/sys/kernel/ngroups_max | 2     | Wed Jan  4 12:33:28 UTC 2023 | Allow  |
| /usr/sbin/apache2 | /tmp/                        | 14    | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
| /usr/sbin/apache2 | /var/www/html/               | 96    | Wed Jan  4 16:53:50 UTC 2023 | Allow  |
+-------------------+------------------------------+-------+------------------------------+--------+


Ingress connections
+----------+-------------------+------------+------+-----------+--------+-------+------------------------------+
| PROTOCOL |      COMMAND      | POD/SVC/IP | PORT | NAMESPACE | LABELS | COUNT |      LAST UPDATED TIME       |
+----------+-------------------+------------+------+-----------+--------+-------+------------------------------+
| TCPv6    | /usr/sbin/apache2 | 127.0.0.1  | 80   |           |        | 6     | Wed Jan  4 12:39:23 UTC 2023 |
+----------+-------------------+------------+------+-----------+--------+-------+------------------------------+


Egress connections
+----------+-------------------+------------------------+------+-----------+--------+-------+------------------------------+
| PROTOCOL |      COMMAND      |       POD/SVC/IP       | PORT | NAMESPACE | LABELS | COUNT |      LAST UPDATED TIME       |
+----------+-------------------+------------------------+------+-----------+--------+-------+------------------------------+
| TCP      | /usr/sbin/apache2 | svc/dvwa-mysql-service | 3306 | dvwa      |        | 15    | Wed Jan  4 12:38:52 UTC 2023 |
+----------+-------------------+------------------------+------+-----------+--------+-------+------------------------------+


Bind Points
+------------+-----------+-----------+--------------+-------+------------------------------+
|  PROTOCOL  |  COMMAND  | BIND PORT | BIND ADDRESS | COUNT |      LAST UPDATED TIME       |
+------------+-----------+-----------+--------------+-------+------------------------------+
| AF_NETLINK | /bin/ping |           |              | 1     | Wed Jan  4 12:33:48 UTC 2023 |
+------------+-----------+-----------+--------------+-------+------------------------------+
```

Key highlights in the above summary:
* Mapping of ingress/egress connections down to the process level.
* Aggregated view of flows, events. The count depicts how many number of times the event occurred.
* Process/File/Ingress/Egress/Bind related information
* Ability to see netlink and unix domain socket connections too.
