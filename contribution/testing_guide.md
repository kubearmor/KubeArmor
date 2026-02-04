# Testing Guide

There are two ways to check the functionalities of KubeArmor: 1) testing KubeArmor manually and 2) using the testing framework.

## Prerequisites

- Install Go **1.24.11** (see the `go` directive in `go.mod`).
- Run a Kubernetes cluster that supports running KubeArmor on the same node as the Kubernetes node(s).

# 0. Make sure Kubernetes cluster is running 

Although there are many ways to run a Kubernetes cluster (like minikube or kind), it will not work with locally developed KubeArmor. KubeArmor needs to be on the same node as where the Kubernetes nodes exist. If you try to do this it will not identify your node since minikube and kind use virtualized nodes. You would either need to build your images and deploy them into these clusters or you can simply use `k3s` or `kubeadm` for development purposes. If you are new to these terms then the easiest way to do this is by following this guide: [K3s installation guide](k3s/README.md)

## 0.1. Firstly Run 'kubectl proxy' in background
```text
$ kubectl proxy &
```
## 0.2. Now run KubeArmor
```text
~/KubeArmor/KubeArmor$ make run
```

# 1.  Test KubeArmor manually

## 1.1. Run 'kubectl proxy' in background

```text
$ kubectl proxy &
```

## 1.2. Compile KubeArmor

```text
$ cd KubeArmor/KubeArmor
~/KubeArmor/KubeArmor$ make clean && make
```

## 1.3. Run KubeArmor

```text
~/KubeArmor/KubeArmor$ sudo -E ./kubearmor -gRPC=[gRPC port number]
                                           -logPath=[log file path]
                                           -enableKubeArmorPolicy=[true|false]
                                           -enableKubeArmorHostPolicy=[true|false]
```

## 1.4. Apply security policies into Kubernetes

Beforehand, check if the KubeArmorPolicy and KubeArmorHostPolicy CRDs are already applied.

```text
$ kubectl explain KubeArmorPolicy
```

If they are still not applied, do so.

```text
$ kubectl apply -f ~/KubeArmor/deployments/CRD/
```

Now you can apply specific policies.

```text
$ kubectl apply -f [policy file]
```

You can refer to security policies defined for example microservices in [examples](../examples).

## 1.5. Trigger policy violations to generate alerts

```text
$ kubectl -n [namespace name] exec -it [pod name] -- bash -c [command]
```

## 1.6. Check generated alerts

- Watch alerts using [karmor](https://github.com/kubearmor/kubearmor-client) cli tool

    ```text
    $ karmor log [flags]
    ```
    
    flags:

    ```text
    --gRPC string        gRPC server information
    --help               help for log
    --json               Flag to print alerts and logs in the JSON format
    --logFilter string   What kinds of alerts and logs to receive, {policy|system|all} (default "policy")
    --logPath string     Output location for alerts and logs, {path|stdout|none} (default "stdout")
    --msgPath string     Output location for messages, {path|stdout|none} (default "none")
    ```
    
    Note that you will see alerts and logs generated right after `karmor` runs logs; thus, we recommend to run the above command in other terminal to see logs live.
    

# 2.  Test KubeArmor using the auto-testing framework
    
- The case that KubeArmor is directly running in a host

    Compile KubeArmor

    ```text
    $ cd KubeArmor/KubeArmor
    ~/KubeArmor/KubeArmor$ make clean && make
    ```

    Run the auto-testing framework

    ```text
    $ cd KubeArmor/tests
    ~/KubeArmor/tests$ ./k8s_env/test-scenarios-local.sh
    ```

    Check the test report

    ```text
    ~/KubeArmor/tests$ cat /tmp/kubearmor.test
    ```

- The case that KubeArmor is running as a daemonset in Kubernetes

    Run the testing framework

    ```text
    $ cd KubeArmor/tests
    ~/KubeArmor/tests$ ./k8s_env/test-scenarios-in-runtime.sh
    ```

    Check the test report

    ```text
    ~/KubeArmor/tests$ cat /tmp/kubearmor.test
    ```

- To run a specific suit of tests move to the directory of test and run
    ```text
    ~/KubeArmor/tests/test_directory$ ginkgo --focus "Suit_Name"
    ```
