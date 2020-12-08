# Example Microservice Deployment

```
$ cd examples/multiubuntu
(examples/multiubuntu) $ kubectl apply -f .
```

# Policy Descriptions

For testing, we provide 8 security policies for the example microservice.

Here is the coverage of those security policies in the containers of the example microservice.

(diagram will be added)

# (Sample) Policy Verification - Blocking a process execution

* Deploying a system policy

```
$ cd security-policies
(security-policies) $ kubectl -n multiubuntu apply -f ksp-group-1-to-sleep.yaml
```

* Executing a command (/bin/sleep)

```
$ kubectl -n multiubuntu exec -it {pod name for ubuntu 1} -- bash
# sleep 1
(Permission Denied)
```

* See audit logs

```
$ kubectl -n kube-system logs {KubeArmor daemon in the node where ubuntu 1 is located}
```

# (Sample) Policy Verification - Blocking a file access

* Deploying a system policy

```
$ cd security-policies
(security-policies) $ kubectl -n multiubuntu apply -f ksp-ubuntu-5-file-dir-recursive-block.yaml
```

* Open a file (/credentials/password)

```
$ kubectl -n multiubuntu exec -it {pod name for ubuntu 5} -- bash
# cat cat /credentials/password
(Permission Denied)
```

* See audit logs

```
$ kubectl -n kube-system logs {KubeArmor daemon in the node where ubuntu 5 is located}
```
