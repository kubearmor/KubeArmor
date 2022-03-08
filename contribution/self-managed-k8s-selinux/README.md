# Kubernetes Installation for SELinux-enabled OS

* Requirements

  You can install Docker and Kubernetes on CentOS 8 or above.

* Prerequisites

  First, install build dependencies (golang, bcc, etc.)
  
  ```text
  $ cd KubeArmor/contribution/self-managed-k8s-selinux
  ~/KubeArmor/contribution/self-managed-k8s-selinux$ ./setup.sh
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
  ~/KubeArmor/contribution/self-managed-k8s-selinux/docker$ ./install_docker.sh
  ~/KubeArmor/contribution/self-managed-k8s-selinux/docker$ exit
  ```
* Kubernetes Installation \(single machine\)

  If you use a machine to set up a single-node environment, Please run the following commands.

  * Master / Worker Node

    Now, you are ready to install Kubernetes. Please run the following commands.

    ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux/k8s
    ~/KubeArmor/contribution/self-managed-k8s-selinux/k8s$ ./install_kubernetes.sh
    ~/KubeArmor/contribution/self-managed-k8s-selinux/k8s$ ./initialize_kubernetes.sh cilium master
    ```

    You can also use other CNIs instead of Cilium.

    ```text
    .../self-managed-k8s-selinux/k8s$ ./initialize_kubernetes.sh [ flannel | weave | calico ] master
    ```

    Please make sure that you need to put "master" at the above command end if you only have a single machine.

* Kubernetes Installation \(multiple machines\)

  If you use multiple machines to set up a multi-node environment, Please run the following commands.

  * Master Node

    ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux/k8s
    ~/KubeArmor/contribution/self-managed-k8s-selinux/k8s$ ./install_kubernetes.sh
    .../self-managed-k8s-selinux/k8s$ ./initialize_kubernetes.sh [ flannel | weave | calico | cilium ] (master)
    ```

    Here, the master node will only serve Kubernetes services since you do not put "master" at the above command end. However, if you also want to use the master node to deploy containers, you can put "master" at the above command end.

  * Worker Node

    ```text
    $ sudo kubeadm ... (the command that you get from the master node)
    ```

* Enable SELinux enforcing mode

  Now, you need to enable SELinux features in all nodes.

  ```text
    $ cd KubeArmor/contribution/self-managed-k8s-selinux
    ~/KubeArmor/contribution/self-managed-k8s-selinux$ ./enable_selinux.sh
  ```
  Then, please wait a couple of minutes for restarting containers.
