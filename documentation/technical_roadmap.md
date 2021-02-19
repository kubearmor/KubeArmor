# Technical Roadmap

Here, we briefly share a plan for next releases \(e.g., including features, specs, and platform supports\).

* Current Release
  * Kubernetes Environments

    - Self-managed Kubernetes \(using kubeadm and MicroK8s\), Google Kubernetes Engine \(GKE\)

  * Container Platforms

    - Docker, Containerd

  * LSM Supports

    - AppArmor

  * Features

    - Monitoring container behaviors at the system level

    - Enforcing security policies against:

    ```text
      Process executions  
      File accesses  
      Network operations  
      Capabilities permitted  
      Resource uses
    ```

    - Producing container-aware audit logs and system logs \(for failed system calls\) and write them into:

    ```text
      Standard output  
      Log file  
      gRPC
    ```
* Next Release
  * Kubernetes Environments

    - \(extension\) Amazon Elastic Kubernetes Service \(EKS\), Azure Kubernetes Service \(AKS\)

  * LSM Supports

    - \(extension\) KRSI \(requiring Linux kernel v5.8 or newer\)

  * Features

    - \(extension\) Producing container-aware logs and write them into:

    ```text
      Database (e.g., MySQL and MongoDB)
    ```

    - Generating security policies for given containers automatically

    ```text
      Process executions  
      Files accesses  
      Network operations
    ```

    - Enforcing security policies at the eBPF level \(using KRSI\)

    ```text
      Process executions  
      File accesses  
      Network operations  
      Capabilities permitted
    ```

    - Produce telemetry data to monitoring systems

    ```text
      Prometheus
    ```
* Future Releases
  * Container Platforms

    - \(extension\) Podman

  * LSM Supports

    - \(extension\) SELinux

  * Features

    - Producing container-aware logs and write them into:

    ```text
      Other systems (e.g., Kafka and Elasticsearch)
    ```

    - Enforcing security policies against inter-container communications at the network level

    ```text
      Integration with network security solutions (e.g., Cilium)
    ```

