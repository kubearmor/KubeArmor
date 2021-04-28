# Kubernetes Installation for SELinux-enabled Fedora OS

* Requirements

  SELinux-enabled Fedora 30 or above.

* Prerequisites

  First, install build dependencies (golang, bcc, etc.)
  
  ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux
    (self-managed-k8s-selinux) $ ./setup.sh
  ```

  Next, disable the swap partition for Kubernetes installation.

  ```text
    $ sudo vi /etc/fstab
    (comment out the line for swap)
    $ sudo reboot
  ```
  
* Docker Installation

  Install Docker through the following commands.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux/docker
    (docker) $ ./install_docker.sh
    (docker) $ exit
  ```
* Kubernetes Installation \(single machine\)

  Now, you are ready to install Kubernetes. Please run the following commands.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux/k8s
    (k8s) $ ./install_kubernetes.sh
    (k8s) $ ./initialize_kubernetes.sh cilium master
  ```

  You can also use other CNIs instead of Cilium.

  ```text
    (k8s) $ ./initialize_kubernetes.sh [ weave | calico | flannel ] master
  ```

  Please make sure that you need to put "master" at the above command end if you only have a single machine.  
  
* Enable SELinux enforcing mode

  Now, you need to enable SELinux features in Docker and kubernetes.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux
    (self-managed-k8s-selinux) $ ./enable_selinux.sh
  ```
  Then, please wait a couple of minutes for restarting containers.
