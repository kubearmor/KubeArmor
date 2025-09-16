# KubeArmor v0.10: Enhancing Visibility and Platform Support

Security update! Announcing the release of KubeArmor v0.10, packed with exciting new features, enhancements, and fixes. This release brings improved default visibility settings, enriched telemetry, and alert data, support for new platforms, and various installation fixes. The community has collaboratively worked to deliver a solid new release. Let’s get into the details of what's new in KubeArmor v0.10:

## Enrichment of Telemetry and Alerts Data
For better visibility, alerts, and telemetry, KubeArmor now includes Deployment Name, Pod Name, Namespace, and Cluster Name. This strategy improves analysis and monitoring, allowing for comprehensive deployments and effective troubleshooting. Added support for deployment scenarios (replicasets, statefulsets, daemonset). This makes it easier for you to base decisions on accurate metadata.  You can now expect even more detailed and insightful information, empowering you to monitor and analyze your workloads with greater precision.

```json
{
  "Timestamp": 1679588263,
  "UpdatedTime": "2023-03-23T16:17:43.146109Z",
  "ClusterName": "default",
  "HostName": "prateek-lenovo-ideapad-310-15isk",
  "NamespaceName": "default",
  "Owner": {
    "Ref": "DaemonSet",
    "Name": "my-daemonset",
    "Namespace": "default"
  },
  "PodName": "my-daemonset-xhrr9",
  "Labels": "app=my-app",
  "ContainerID": "0e6a98ec00521ed92fd29664ae238f60463a93b819e6c54a4494cf371e63e86a",
  "ContainerName": "my-container",
  "ContainerImage": "docker.io/library/nginx:latest@sha256:1ed4dff2b99011798f2c228667d7cb4f4e2bd76b2adc78fd881d39f923e78c9d",
  "HostPPID": 671928,
  "HostPID": 672009,
  "PPID": 41,
  "PID": 46,
  "ParentProcessName": "/bin/bash",
  "ProcessName": "/bin/sleep",
  "PolicyName": "new",
  "Severity": "5",
  "Message": "block /bin/sleep",
  "Type": "MatchedPolicy",
  "Source": "/bin/bash",
  "Operation": "Process",
  "Resource": "/bin/sleep",
  "Data": "syscall=SYS_EXECVE",
  "Enforcer": "AppArmor",
  "Action": "Block",
  "Result": "Permission denied"
}
```

Note the availability of `owner` nested json in the above telemetry event that provides details about the owner references that generated this telemetry event.

## Support for BPF-LSM in Non-Orchestrated Containerized Workloads
In the previous versions, enforcement in containerized workloads was limited to AppArmor. We are delighted to introduce support for BPF-LSM (Linux Security Modules) in non-orchestrated containerized workloads. This new capability allows you to leverage the benefits of BPF-based security policies even outside of orchestrated environments. You can now avail the benefits of BPF LSM for enhanced security and fine-grained control over containerized workloads.

By incorporating BPF LSM enforcement, KubeArmor enables users to define and enforce security policies at the kernel level, providing an additional layer of protection for their containerized environments. Advanced capabilities offered by BPF LSM, including powerful eBPF (extended Berkeley Packet Filter) programs and flexible security rules, are now unlocked!

![image](https://github.com/kubearmor/KubeArmor/assets/9133227/62d45528-bb4d-4ec8-a65e-8d2a3472dc9b)

## Helm Installation Fixes
For smoother deployments using Helm, we have addressed several issues and made necessary fixes. To benefit from these improvements, please refer to our updated [Helm installation guide](https://github.com/kubearmor/KubeArmor/tree/main/deployments/helm). If you are still facing any issues, please put it up in the [discussions](https://github.com/kubearmor/KubeArmor/discussions).

![image](https://github.com/kubearmor/KubeArmor/assets/9133227/5c882a40-d27c-488e-9493-b3e65f6c6cda)

## Auto-Updating Dependencies
To ensure you always have the latest dependencies, KubeArmor now utilizes Renovate, an automated dependency update tool. With Renovate, you can expect a seamless experience, as KubeArmor keeps your dependencies up to date automatically. Everything synced!

![image](https://github.com/kubearmor/KubeArmor/assets/9133227/472eef4a-24eb-4b9a-8078-9de739399449)

## Support for New Platforms
With this release, we have expanded our platform support to include:
1. DigitalOcean [Kubernetes ](https://www.digitalocean.com/products/kubernetes)(DOKs)
2. Mirantis MKE.
3. Amazon Linux 2023.

<img width="491" alt="image" src="https://github.com/kubearmor/KubeArmor/assets/9133227/779da08a-0de4-4482-83b4-fb9cab16e7b9">

This means you can now confidently run KubeArmor on these platforms, benefiting from enhanced security and protection.

## Default Visibility Changes
In previous versions, KubeArmor enabled full telemetry by default for all workloads. With v0.10, we have made a significant change. By default, telemetry for workloads is now disabled, offering more flexibility in managing telemetry settings. If you want to enable telemetry for specific workloads or namespaces, you can easily do so using [annotations](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/kubearmor_visibility.md).

## Miscellaneous

We are grateful to our dedicated community for their continuous support and valuable contributions that have made this release possible. Your feedback and suggestions drive us to improve KubeArmor with every release.

To explore the complete list of changes, bug fixes, and enhancements in KubeArmor v0.10, please refer to our [release notes](https://github.com/kubearmor/KubeArmor/releases/tag/v0.10.2).

Upgrade to KubeArmor v0.10 today and experience the latest features and fixes firsthand. We look forward to hearing your thoughts and helping you strengthen the security of your Kubernetes deployments.

Got any questions? Check out the [FAQ](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/FAQ.md) page or join the [KubeArmor Slack](https://join.slack.com/t/kubearmor/shared_invite/zt-1ltmqdbc6-rSHw~LM6MesZZasmP2hAcA) for support.

Stay tuned for more updates and exciting features on our roadmap. Together, let's build a more secure and resilient Kubernetes ecosystem!