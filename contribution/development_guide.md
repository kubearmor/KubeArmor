# Development Guide

## Development

1. Vagrant Environment (Recommended)
   * Requirements

     Here is the list of requirements for a Vagrant environment

     ```text
     Vagrant - v2.2.9
     VirtualBox - v6.1
     ```

     Clone the KubeArmor github repository in your system

     ```text
     $ git clone https://github.com/kubearmor/KubeArmor.git
     ```

     Install Vagrant and VirtualBox in your environment, go to the vagrant path and run the setup.sh file

     ```text
     $ cd KubeArmor/contribution/vagrant
     ~/KubeArmor/contribution/vagrant$ ./setup.sh
     ```

    * VM Setup using Vagrant

      Now, it is time to prepare a VM for development.

      To create a vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-up
      ```

      Output will show up as ...

      <details>
      <summary>Click to expand!</summary>
  
      ```text
      cd /home/gourav/KubeArmor/contribution/vagrant; NETNEXT=0 DLV_RPORT=2345 vagrant up; true
      Bringing machine 'kubearmor-dev' up with 'virtualbox' provider...
      ==> kubearmor-dev: Importing base box 'ubuntu/bionic64'...
      ==> kubearmor-dev: Matching MAC address for NAT networking...
      ==> kubearmor-dev: Checking if box 'ubuntu/bionic64' version '20220131.0.0' is up to date...
      ==> kubearmor-dev: Setting the name of the VM: kubearmor-dev
      ==> kubearmor-dev: Clearing any previously set network interfaces...
      ==> kubearmor-dev: Preparing network interfaces based on configuration...
          kubearmor-dev: Adapter 1: nat
      ==> kubearmor-dev: Forwarding ports...
          kubearmor-dev: 2345 (guest) => 2345 (host) (adapter 1)
          kubearmor-dev: 22 (guest) => 2222 (host) (adapter 1)
      ==> kubearmor-dev: Running 'pre-boot' VM customizations...
      ==> kubearmor-dev: Booting VM...
      ==> kubearmor-dev: Waiting for machine to boot. This may take a few minutes...
          kubearmor-dev: SSH address: 127.0.0.1:2222
          kubearmor-dev: SSH username: vagrant
          kubearmor-dev: SSH auth method: private key
          kubearmor-dev: Warning: Connection reset. Retrying...
          kubearmor-dev: Warning: Remote connection disconnect. Retrying...
          kubearmor-dev:
          kubearmor-dev: Vagrant insecure key detected. Vagrant will automatically replace
          kubearmor-dev: this with a newly generated keypair for better security.
          kubearmor-dev:
          kubearmor-dev: Inserting generated public key within guest...
          kubearmor-dev: Removing insecure key from the guest if it's present...
          kubearmor-dev: Key inserted! Disconnecting and reconnecting using new SSH key...
      ==> kubearmor-dev: Machine booted and ready!
      ==> kubearmor-dev: Checking for guest additions in VM...
          kubearmor-dev: The guest additions on this VM do not match the installed version of
          kubearmor-dev: VirtualBox! In most cases this is fine, but in rare cases it can
          kubearmor-dev: prevent things such as shared folders from working properly. If you see
          kubearmor-dev: shared folder errors, please make sure the guest additions within the
          kubearmor-dev: virtual machine match the version of VirtualBox you have installed on
          kubearmor-dev: your host and reload your VM.
          kubearmor-dev:
          kubearmor-dev: Guest Additions Version: 5.2.42
          kubearmor-dev: VirtualBox Version: 6.1
      ==> kubearmor-dev: Setting hostname...
      ==> kubearmor-dev: Mounting shared folders...
          kubearmor-dev: /vagrant => /home/gourav/KubeArmor/contribution/vagrant
          kubearmor-dev: /home/vagrant/KubeArmor => /home/gourav/KubeArmor
      ==> kubearmor-dev: Running provisioner: file...
          kubearmor-dev: ~/.ssh/id_rsa.pub => /home/vagrant/.ssh/id_rsa.pub
      ==> kubearmor-dev: Running provisioner: shell...
          kubearmor-dev: Running: inline script
      ==> kubearmor-dev: Running provisioner: file...
          kubearmor-dev: ~/.gitconfig => $HOME/.gitconfig
      ==> kubearmor-dev: Running provisioner: shell...
          kubearmor-dev: Running: /tmp/vagrant-shell20220202-55671-bn8u0f.sh
          ...
      ```
      </details>

      To get into the vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-ssh
      ```

      Output will show up as ...

      <details>
      <summary>Click to expand!</summary>
  
      ```text
      d /home/gourav/KubeArmor/contribution/vagrant; NETNEXT=0 DLV_RPORT=2345 vagrant ssh; true
      Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-167-generic x86_64)

       * Documentation:  https://help.ubuntu.com
       * Management:     https://landscape.canonical.com
       * Support:        https://ubuntu.com/advantage

        System information as of Wed Feb  2 10:35:55 UTC 2022

        System load:  0.06               Processes:              128
        Usage of /:   11.1% of 38.71GB   Users logged in:        0
        Memory usage: 10%                IP address for enp0s3:  10.0.2.15
        Swap usage:   0%                 IP address for docker0: 172.17.0.1


      5 updates can be applied immediately.
      1 of these updates is a standard security update.
      To see these additional updates run: apt list --upgradable

      New release '20.04.3 LTS' available.
      Run 'do-release-upgrade' to upgrade to it.


      vagrant@kubearmor-dev:~$
      ```
      </details>

      To destroy the vagrant VM

      ```text
      ~/KubeArmor/KubeArmor$ make vagrant-destroy
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

2. Self-managed Kubernetes
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

      * Alternative Setup - Minikube

        MiniKube does not support LSMs by default; thus, you cannot test KubeArmor on Minikube. However, we provide the custom ISO image for testing KubeArmor on Minikube.  
        Please follow the instructions in [Minikube installation guide](minikube/README.md).

      * Alternative Setup - K3s

        You can also develop and test KubeArmor on K3s instead of the self-managed Kubernetes.  
        Please follow the instructions in [K3s installation guide](k3s/README.md).

      * Alternative Setup - MicroK8s

        You can also develop and test KubeArmor on MicroK8s instead of the self-managed Kubernetes.  
        Please follow the instructions in [MicroK8s installation guide](microk8s/README.md).

      * No Support - Docker Desktops

        KubeArmor does not work with Docker Desktops on Windows and macOS because KubeArmor integrates with Linux-kernel native primitives (including LSMs).

   * Development Setup

     In order to install all dependencies, please run the following command.

     ```text
     $ cd KubeArmor/contribution/self-managed-k8s
     ~/KubeArmor/contribution/self-managed-k8s$ ./setup.sh
     ```

     [setup.sh](self-managed-k8s/setup.sh) will automatically install BCC, Go, Protobuf, and some other dependencies.

     Now, you are ready to develop any code for KubeArmor. Enjoy your journey with KubeArmor.

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
    config               - Configuration loader
    core                 - The main body (start point) of KubeArmor
    enforcer             - Runtime policy enforcer (enforcing security policies into LSMs)
    feeder               - gRPC-based feeder (sending audit/system logs to a log server)
    log                  - Message logger (stdout)
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
