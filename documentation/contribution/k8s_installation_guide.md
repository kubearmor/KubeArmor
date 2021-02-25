# Kubernetes Installation

* Requirements

  You can install Docker and Kubernetes in any Ubuntu platforms.

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
    $ cd KubeArmor/contributions/bare-metal/docker
    (docker) $ ./install_docker.sh
    (docker) $ exit
  ```

* Kubernetes Installation \(single machine\)

  Now, you are ready to install Kubernetes. Please run the following command.

  ```text
    $ cd KubeArmor/contributions/bare-metal/k8s
    (k8s) $ ./install_kubernetes.sh
    (k8s) $ ./initialize_kubernetes.sh flannel master
  ```

  Instead of Flannel, you can use other CNIs too.

  ```text
    (k8s) $ ./initialize_kubernetes.sh [ weave | calico | cilium ] master
  ```

  Please make sure that you need to put "master" at the above command end if you have only a single machine.

* Kubernetes Installation \(multiple machines\)

  If you use multiple machines to set up a multi-node environment, Please run the following command.

  * Master Node

    ```text
    $ cd KubeArmor/contributions/bare-metal/k8s
    (k8s) $ ./install_kubernetes.sh
    (k8s) $ ./initialize_kubernetes.sh [ flannel | weave | calico | cilium ] (master)
    ```

    Here, the master node will only serve Kubernetes services since you do not put "master" at the above command end. However, if you also want to use the master node to deploy containers, you can put "master" at the above command end.

  * Worker Node

    ```text
    $ sudo kubeadm ... (the command that you get from the master node)
    ```
