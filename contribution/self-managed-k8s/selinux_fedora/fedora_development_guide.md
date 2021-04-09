# KubeArmor development in Fedora 30 with SELinux Installation

* Requirements

  You can install Docker and Kubernetes on any fedora platform with SELinux-enabled.

* Prerequisites

  First, you need to install build dependencies (golang, bcc, etc.)
  
  ```text
    $ cd KubeArmor/contribution/self-managed-k8s/selinux_fedora
    $ ./setup
  ```

  Next, you need to disable the swap partition in advance for Kubernetes setup.

  ```text
    $ sudo vi /etc/fstab
    (comment out the line for swap)
    $ sudo reboot
  ```
  
* Docker Installation

  You can simply install Docker through the following command.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s/selinux_fedora/docker
    (docker) $ ./install_docker.sh
    (docker) $ exit
  ```
* Kubernetes Installation \(single machine\)

  Now, you are ready to install Kubernetes. Please run the following command.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s/selinux_fedora/k8s
    (k8s) $ ./install_kubernetes.sh
    (k8s) $ ./initialize_kubernetes.sh cilium master
  ```

  Instead of Cilium, you can use other CNIs too.

  ```text
    (k8s) $ ./initialize_kubernetes.sh [ weave | calico | flannel ] master
  ```

  Please make sure that you need to put "master" at the above command end if you have only a single machine.  
  
* Enable SELinux enforcing

  Now, you need to enable SELinux in Docker & kubernetes.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s/selinux_fedora
    $ ./enable_selinux.sh
  ```
  Then, please wait a couple of minutes for restarting the containers.
