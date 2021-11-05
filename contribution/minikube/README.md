# Minikube Installation

KubeArmor basically requires LSMs. However, if you want to use Minikube instead of self-managed Kubernetes or MicroK8s, please run the following commands.

```text
$ cd KubeArmor/contribution/minikube
~/KubeArmor/contribution/minikube$ ./install_virtualbox.sh
~/KubeArmor/contribution/minikube$ sudo reboot
```

After rebooting the machine, please keep running the following commands.

```text
$ cd KubeArmor/contribution/minikube
~/KubeArmor/contribution/minikube$ ./install_minikube.sh
```

Ensure to use virtualbox driver when running minikube. This step is necessary in order to mount roofs as read/write.

```text
$ minikube config set driver virtualbox
```

In order to use KubeArmor, Minikube needs to support eBPF capabilities. Unfortunately, Minikube doesn't suuport them by default. Thus, please run the following command rather than simply running "minikube start".

```text
~/KubeArmor/contribution/minikube$ ./start_minikube.sh
```

It will use the minikube image with Linux kernel 4.19.94 and download the Linux kernel 4.19.94 headers.

To check if eBPF programs run in Minikube, please run the following command.

```text
~/KubeArmor/contribution/minikube$ ./test_ebpf.sh
```

If you see no error, you're ready to test KubeArmor.
