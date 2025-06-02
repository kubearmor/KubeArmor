# Tutorial: KubeArmor

KubeArmor is a **runtime security enforcement system** for containers and nodes.
It uses _security policies_ (defined as Kubernetes Custom Resources like KSP, HSP, and CSP)
to define allowed, audited, or blocked actions for workloads.
The system _monitors system activity_ using kernel technologies such as eBPF
and enforces the defined policies by integrating with the underlying operating system's
security modules like AppArmor, SELinux, or BPF-LSM, sending security alerts
and telemetry through a log feeder.

## Visual Overview

```mermaid
flowchart TD
    A0["Security Policies (KSP, HSP, CSP)
"]
    A1["System Monitor
"]
    A2["Runtime Enforcer
"]
    A3["BPF (eBPF)
"]
    A4["Container/Node Identity
"]
    A5["KubeArmor Daemon
"]
    A6["Log Feeder
"]
    A5 -- "Initializes/Manages" --> A1
    A5 -- "Initializes/Manages" --> A2
    A5 -- "Watches/Receives" --> A0
    A0 -- "Configures" --> A2
    A2 -- "Uses for enforcement" --> A3
    A1 -- "Uses for monitoring" --> A3
    A3 -- "Reports events to" --> A1
    A1 -- "Uses for context" --> A4
    A5 -- "Discovers/Tracks" --> A4
    A1 -- "Sends logs to" --> A6
```
