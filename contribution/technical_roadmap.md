# Technical Roadmap

* KubeArmor v1.1

  * Kubernetes Environments
    * Self-managed Kubernetes \(using kubeadm\), MicroK8s, Minikube*
    * Google Kubernetes Engine \(GKE\), Amazon Elastic Kubernetes Service \(EKS\)\*, Azure Kubernetes Service \(AKS\)\*

  * Container Platforms
    * Docker, Containerd

  * LSM Supports
    * AppArmor, SELinux*

  * Features
    * (KubeArmorPolicy) Add a new field, "apparmor" in KubeArmorPolicy*
      ```text
      (AppArmor) Apply native AppArmor profiles using KubeArmorPolicy
      ```

    * (KubeArmorPolicy) Add a new field, "selinux -> volumeMounts" in KubeArmorPolicy*
      ```text
      (SELinux) Apply SELinux labels and actions to control the access of VolumeMounts using KubeArmorPolicy
      ```

    * (KubeArmorHostPolicy) Support security policies for hosts*
      ```text
      Apply security policies to restrict host resources (e.g., processes and files in hosts)
      ```

    * (Audit Mode) Provide the audit mode if no LSM is enabled in hosts*
      ```textg
      Keep auditing the behavior of containers based on given policies
      In the audit mode, actions are changed as follows:
      - Allow -> Audit (Allow)
      - Audit -> Audit
      - Block -> Audit (Block)
      ```

    * Monitor container behaviors at the system level

    * Enforce security policies against:
      ```text
      Process executions
      File accesses
      Network operations
      Capabilities permitted
      ```

    * Produce container-aware alerts and system logs and write them into:
      ```text
      Standard output
      Log file
      gRPC
      ```

    * Provide gRPC clients*
      ```text
      kubearmor-log-client (https://github.com/kubearmor/kubearmor-log-client)
      kubearmor-mysql-client* (https://github.com/kubearmor/kubearmor-mysql-client)
      kubearmor-kafka-client* (https://github.com/kubearmor/kubearmor-kafka-client)
      ```

    * Produce telemetry data to monitoring systems*
      ```text
      Prometheus integration* (https://github.com/kubearmor/kubearmor-prometheus-exporter)
      ```

  Node that we add a symbol (*) for new features.

* KubeArmor v1.0

  * Kubernetes Environments
    * Self-managed Kubernetes \(using kubeadm\), MicroK8s
    * Google Kubernetes Engine \(GKE\)

  * Container Platforms
    * Docker, Containerd

  * LSM Support
    * AppArmor

  * Features
    * Monitor container behaviors at the system level

    * Enforce security policies against:
      ```text
      Process executions
      File accesses
      Network operations
      Capabilities permitted
      ```

    * Produce container-aware alerts and system logs and write them into:
      ```text
      Standard output
      Log file
      gRPC
      ```

    * Provide gRPC clients
      ```text
      kubearmor-log-client (https://github.com/kubearmor/kubearmor-log-client)
      ```

* KubeArmor Roadmap for future releases
  * Container Platforms
    * OpenShift, PodMan

  * LSM Supports
    * LSM eBPF (KRSI)

  * Features
    * Automatically generate security policies for given containers against:
      ```text
      Process executions
      Files accesses
      ```

    * Enforce security policies \(using LSM eBPF\) against:
      ```text
      Process executions
      File accesses
      Network operations
      Capabilities permitted
      ```

    * Enforce security policies against inter-container communications at the network level
      ```text
      Integration with network security solutions (e.g., Cilium)
      ```
