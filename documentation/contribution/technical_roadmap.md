# Technical Roadmap

Here, we briefly share a plan for next releases \(e.g., including features, specs, and platform supports\).

* Current Release

  * Kubernetes Environments

    * Self-managed Kubernetes \(using kubeadm\), MicroK8s, Google Kubernetes Engine \(GKE\)

  * Container Platforms

    * Docker, Containerd

  * LSM Supports

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

    * Produce container-aware audit logs and system logs \(for failed system calls\) and write them into:

    ```text
      Standard output  
      Log file  
      gRPC
    ```

* Next Release

  * Kubernetes Environments

    * \(extension\) Amazon Elastic Kubernetes Service \(EKS\), Azure Kubernetes Service \(AKS\)

  * LSM Supports

    * \(extension\) KRSI \(requiring Linux kernel v5.8 or newer\)

  * Features

    * \(extension\) Produce container-aware logs and write them into:

    ```text
      Database (e.g., MySQL and MongoDB)
    ```

    * Automatically generate security policies for given containers against:

    ```text
      Process executions  
      Files accesses
    ```

    * Enforce security policies \(using KRSI\) against:

    ```text
      Process executions  
      File accesses  
      Network operations  
      Capabilities permitted
    ```

    * Produce telemetry data to monitoring systems

    ```text
      Prometheus
    ```

* Future Releases

  * Container Platforms

    * \(extension\) Podman

  * LSM Supports

    * \(extension\) SELinux

  * Features

    * Produce container-aware logs and write them into:

    ```text
      Other systems (e.g., Kafka and Elasticsearch)
    ```

    * Enforce security policies against inter-container communications at the network level

    ```text
      Integration with network security solutions (e.g., Cilium)
    ```
