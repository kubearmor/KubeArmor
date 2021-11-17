# Development Guide

## Development

1. Self-managed Kubernetes
   * Requirements

     List of minimum requirements for self-managed Kubernetes.
     ```text
     OS - Ubuntu 18.04
     Kubernetes - v1.19
     Docker - 18.09 or Containerd - 1.3.7
     Linux Kernel - v4.15
     LSM - AppArmor
     ```

     KubeArmor is designed for Kubernetes, which means that Kubernetes should be ready in your environment. If Kubernetes is not prepared yet, please refer to [Kubernetes installation guide](self-managed-k8s/README.md). KubeArmor also requires either Docker or Containerd since it internally uses its APIs. KubeArmor requires LSMs to operate properly; thus, please make sure that your environment supports LSMs \(at least, AppArmor\). Otherwise, KubeArmor will work as Audit-Mode with no container behavior restriction.

      * Alternative Setup - MicroK8s

        You can also develop and test KubeArmor on MicroK8s instead of the self-managed Kubernetes. For this, please follow the instructions in [MicroK8s installation guide](microk8s/README.md).

      * Alternative Setup - K3s

        You can also develop and test KubeArmor on K3s instead of the self-managed Kubernetes. For this, please follow the instructions in [K3s installation guide](k3s/README.md).

      * Notice - Minikube

        KubeArmor does not support the policy enforcement on Minikube because MiniKube does not support LSMs, which means that you will only get the alerts against given policy violations. However, if you want to test KubeArmor, you can follow the instructions in [Minikube installation guide](minikube/README.md).

      * Caution - Docker Desktops

        KubeArmor does not work with Docker Desktops on Windows and macOS because KubeArmor integrates with Linux-kernel native primitives (including LSMs).

   * Development Setup

     In order to install all dependencies, please run the following command.

     ```text
     $ cd KubeArmor/contribution/self-managed-k8s
     ~/KubeArmor/contribution/self-managed-k8s$ ./setup.sh
     ```

     [setup.sh](self-managed-k8s/setup.sh) will automatically install BCC, Go, Protobuf, and some other dependencies.

     Now, you are ready to develop any code for KubeArmor. Enjoy your journey with KubeArmor.

2. Vagrant Environment (Recommended)
   * Requirements

     Here is the list of requirements for a Vagrant environment

     ```text
     Vagrant - v2.2.9
     VirtualBox - v6.1
     ```

     If you do not have Vagrant and VirtualBox in your environment, you can easily install them by running the following command.

     ```text
     cd KubeArmor/contribution/vagrant
     ~/KubeArmor/contribution/vagrant$ ./setup.sh
     ```

    * VM Setup using Vagrant

      Now, it is time to prepare a VM for development.

      To create a vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-up
      ```

	    To destroy the vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-destroy
      ```

      To get into the vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-ssh
      ```

    * VM Setup using the latest Linux kernel (v5.13)

      To use the latest linux kernel for dev env you can run `make` with the `NETNEXT` flag set to `1` for the respective make option.

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-up NETNEXT=1
      ```

       You can also make the setting static by changing `NETNEXT=0` to `NETNEXT=1` in the Makefile.

      ```text
      ~/KubeArmor/KubeArmor$ vi Makefile
      ```

    * Please Note:

      You could skip vagrant step completely if you're directly compiling Kubearmor on any Linux distro, or using Virtualbox.

      Please ensure that the steps to setup K8s is followed so as to resolve any open dependencies.

3.  Environment Check
    * Compilation

        Check if KubeArmor can be compiled on your environment without any problems.

        ```text
        $ cd KubeArmor/KubeArmor
        ~/KubeArmor/KubeArmor$ make
        ```

        If you see any error messages, please let us know the issue with the full error messages through KubeArmor's slack.

    * Execution

        In order to directly run KubeArmor in a host (not as a container), you need to run a local proxy in advance.

        ```text
        $ kubectl proxy &
        ```

        Then, run KubeArmor on your environment.

        ```text
        $ cd KubeArmor/KubeArmor
        ~/KubeArmor/KubeArmor$ make run
        ```

## Code Directories

Here, we briefly give you an overview of KubeArmor's directories.

* Source code for KubeArmor \(/KubeArmor\)

  ```text
  KubeArmor/
    BPF                  - eBPF code for system monitor
    common               - Libraries internally used
    core                 - The main body (start point) of KubeArmor
    enforcer             - Runtime policy enforcer (enforcing security policies into LSMs)
    feeder               - gRPC-based feeder (sending audit/system logs to a log server)
    log                  - Message logger (stdout) for KubeArmor
    monitor              - eBPF-based system monitor (mapping process IDs to container IDs)
    types                - Type definitions
  protobuf/              - Protocol buffer
  ```

* Source code for KubeArmor's custom resource definition \(CRD\)

  ```text
  pkg/KubeArmorPolicy/      - KubeArmorPolicy CRD generated by Kube-Builder
  pkg/KubeArmorHostPolicy/  - KubeArmorHostPolicy CRD generated by Kube-Builder
  ```

* Scripts for GKE

  ```text
  GKE/          - scripts to set up the enforcer in a container-optimized OS (COS)
  ```

* Files for testing

  ```text
  examples/     - Example microservices for testing
  tests/        - Automated test framework for KubeArmor
  ```
