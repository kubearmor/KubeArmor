# Technical Roadmap

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
  * Kubernetes Environments
    * Minikube, OpenShift
    * Amazon Elastic Kubernetes Service \(EKS\), Azure Kubernetes Service \(AKS\)

  * Container Platforms
    * PodMan

  * LSM Supports
    * SELinux, LSM eBPF (KRSI)

  * Features
    * Provide gRPC clients
      ```text
      kubearmor-mysql-client
      kubearmor-kafka-client
      ```
    * Produce telemetry data to monitoring systems
      ```text
      Prometheus integration
      ```
    * Automatically generate security policies for given containers against:
      ```text
      Process executions
      Files accesses
      ```
    * Enforce security policies against inter-container communications at the network level
      ```text
      Integration with network security solutions (e.g., Cilium)
      ```
