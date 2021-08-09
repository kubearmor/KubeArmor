# Kubernetes Installation for AppArmor-enabled Ubuntu OS

* Requirements

  You can install Docker and Kubernetes on any Ubuntu platform (e.g., 18.04, 20.04).

* Prerequisites

  You need to disable the swap partition in advance for Kubernetes setup.

  ```text
  $ sudo vi /etc/fstab
  (comment out the line for swap)
  $ sudo reboot
  ```

* Docker Installation

  You can simply install Docker through the following command.

  ```text
  $ cd KubeArmor/contribution/self-managed-k8s/docker
  ~/KubeArmor/contribution/self-managed-k8s/docker$ ./install_docker.sh
  ~/KubeArmor/contribution/self-managed-k8s/docker$ exit
  ```

* Kubernetes Installation \(single machine\)

  If you use multiple machines to set up a single-node environment, Please run the following commands.

  * Master/Worker Node

    ```text
    $ cd KubeArmor/contribution/self-managed-k8s/k8s
    ~/KubeArmor/contribution/self-managed-k8s/k8s$ ./install_kubernetes.sh
    ~/KubeArmor/contribution/self-managed-k8s/k8s$ ./initialize_kubernetes.sh cilium master
    ```

    You can also use other CNIs instead of Cilium.

    ```text
    .../self-managed-k8s/k8s$ ./initialize_kubernetes.sh [ flannel | weave | calico ] master
    ```

  Please make sure that you need to put "master" at the above command end if you have only a single machine.

* Kubernetes Installation \(multiple machines\)

  If you use multiple machines to set up a multi-node environment, Please run the following commands.

  * Master Node

    ```text
    $ cd KubeArmor/contribution/self-managed-k8s/k8s
    ~/KubeArmor/contribution/self-managed-k8s/k8s$ ./install_kubernetes.sh
    .../self-managed-k8s/k8s$ ./initialize_kubernetes.sh [ flannel | weave | calico | cilium ] (master)
    ```

    Here, the master node will only serve Kubernetes services since you do not put "master" at the above command end. However, if you also want to use the master node to deploy containers, you can put "master" at the above command end.

  * Worker Node

    ```text
    $ sudo kubeadm ... (the command that you get from the master node)
    ```
