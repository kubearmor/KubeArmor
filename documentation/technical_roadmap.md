# Technical Roadmap

Here, we briefly share a plan for next releases (e.g., including features, specs, and platform supports).

- Current Release

    - Kubernetes Environments
    
        \- Self-managed Kubernetes, Google Kubernetes Engine (GKE)
    
    - Container Platforms
    
        \- Docker
        
    - LSM Supports
    
        \- AppArmor

    - Features
    
        \- Enforcing security policies against:

            Process executions (through AppArmor)  
            File accesses (through AppArmor)  
            Network operations according to protocols (through AppArmor)  
            Capabilities permitted (through AppArmor)

        \- Producing container-aware audit logs and write them into:
        
            Standard output  
            Log file

        \- Monitoring container behaviors at the system level

- Next Release

    - Kubernetes Environments
    
        \- (extension) Amazon Elastic Kubernetes Service (EKS), Azure Kubernetes Service (AKS)
    
    - Container Platforms
    
        \- (extension) Containerd
        
    - LSM Supports
    
        \- (extension) KRSI (requiring Linux kernel v5.8 or newer)

    - Features
    
        \- (extension) Enforcing security policies against:
        
            System-wide operations instead of specific capabilities (through AppArmor)  
            Resource utilization (through AppArmor)

        \- (extension) Producing container-aware audit logs and write them into:
        
            Database (e.g., MySQL and MongoDB)

        \- Generating security policies for given containers automatically
        
            Process executions  
            Files accesses

        \- Enforcing security policies at the eBPF level (using KRSI)

            Process executions  
            File accesses  
            Network operations according to protocols, IP addresses and ports (socket level)  
            Capabilities permitted

- Future Releases

    - Container Platforms
    
        \- (extension) Podman
        
    - LSM Supports
    
        \- (extension) SELinux

    - Features
    
        \- (extension) Enforcing security policies at the eBPF level (using KRSI)
        
            Let's keep track of the features updated from KRSI

        \- Producing container-aware audit logs and write them into:
        
            Other platforms (e.g., gRPC, Kafka and Elasticsearch)
    
        \- Enforcing security policies against inter-container communications at the network level
        
            Integration with network security solutions (e.g., Cilium)
