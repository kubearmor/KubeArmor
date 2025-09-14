# KubeArmor v0.11 Release: Elevating Container Security for Kubernetes Environments

We're thrilled to introduce the latest release of KubeArmor, version v0.11! This significant update reinforces our commitment to providing top-tier container-level security for Kubernetes deployments. With an array of new features, integrations, and improvements, KubeArmor v0.11 empowers you to achieve even greater security and control over your containerized workloads. Let's delve into the key highlights of this release:

## Operator support: Simplifying Management and Deployment

<img src="https://github.com/kubearmor/KubeArmor/assets/9133227/6bfe1636-cbce-49b3-8ae5-3df01c94510a" width="60%">

KubeArmor v0.11 comes with robust operator support, making the installation, configuration, and management of KubeArmor instances a breeze. The KubeArmor Operator streamlines the deployment process, enabling you to efficiently set up and maintain KubeArmor across your Kubernetes clusters. Embrace simplicity and consistency in managing your security policies.

Elements of KubeArmor Operator design:
* **Operator**: Operator is the initial component that gets deployed as part of helm based installation. The job of the operator is to reconcile the current state of KubeArmor to its intended state.
* **Snitch**: Snitch is a job deployed by operator to check what is the prevalent LSM (Linux Security Modules) and the container runtime on each of the node. Snitch then directs the KubeArmor daemonset to use these parameters to accordingly use the appropriate enforcer and container runtime primitives.
* **bpf-containerd**: This is essentially the KubeArmor daemonset that does most of the work from observability to policy enforcement. Note that the name of the daemonset is dependent on the underlying enforcer (bpf, apparmor) that is used and the container runtime that is detected.
* **Relay**: KubeArmor Relay connects to each of the daemonset and collects the alerts/telemetry/log and makes it available at single GRPC endpoint. External services can connect to KubeArmor Relay to gets the alerts/telemetry from a single point. Relay is available as a k8s deployment/service.
* **Controller**: KubeArmor controller reconciles the KubeArmor policies. One of the biggest advantage of KubeArmor is its use of k8s-native design for policy management. Users can enable disable policies at will by applying/deleting the policies at runtime. This enables a wide range of possibilities such as time-based policy activation.

## OpenTelemetry

<img src="https://github.com/kubearmor/KubeArmor/assets/9133227/4f98fc7c-2c5c-4200-b3e4-9f4fb78ce26a" width="60%">

The [OpenTelemetry KubeArmor](https://github.com/kubearmor/otel-adapter) adapter converts KubeArmor telemetry data (logs, visibilty events, policy violations) to the openTelemetry format. This [adds opentelemetry support to KubeArmor](https://github.com/kubearmor/KubeArmor/issues/894) providing a vendor agnostic means of exporting KubeArmor's telemetry data to various observability backend such as [elastic search](https://www.elastic.co/guide/en/apm/guide/current/open-telemetry-direct.html#connect-open-telemetry-collector), [grafana](https://grafana.com/docs/opentelemetry/collector/), [signoz](https://signoz.io/blog/opentelemetry-apm/) and a bunch of other [opentelemetry adopters](https://github.com/open-telemetry/community/blob/main/ADOPTERS.md)!

To enhance your observability capabilities, KubeArmor now seamlessly integrates with Open Telemetry. Gain unparalleled insights into container behavior and workload interactions through comprehensive telemetry data collection. With this integration, you'll be equipped to make informed decisions, swiftly identify anomalies, and proactively address potential security threats.

Credits: Amazing work by [Maureen Ononiwu](https://github.com/Chinwendu20) for handling KubeArmor's OpenTelemetry integration as part of LFX Mentorship. :rocket:

## Announcing k8tls (pronounced cattles): k8s service endpoints TLS best practices assessment

<img src="https://github.com/kubearmor/KubeArmor/assets/9133227/49ae41fe-a724-41d0-b8f1-d5b3b8bf778b" width="30%">

Security extends beyond containers. KubeArmor v0.11 introduces [k8tls](https://github.com/kubearmor/k8tls) to bolster transport layer security within Kubernetes clusters. Safeguard your communications with enhanced encryption, safeguarding your data and ensuring the confidentiality of sensitive information.

[K8tls](https://github.com/kubearmor/k8tls) is a k8s-native service endpoint scanning engine that verifies whether the endpoint is using secure communication and is using right security configuration. K8tls deploys itself as a k8s job that scans/fingerprints k8s service endpoints to identify if TLS best practices are followed. Primary features include:

* 🔒 Check if the server port is TLS enabled or not.
* 📃 Check TLS version, Ciphersuite, Hash, and Signature for the connection. Are these TLS parameters per the TLS best practices guide?
* Certificate Verification
    * 💥 Is the certificate expired or revoked?
    * ✍️ Is it a self-signed certificate?
    * ⛓️ Is there a self-signed certificate in the full certificate chain?

## KubeArmor as Canonical Microk8s Addon

<img src="https://github.com/kubearmor/KubeArmor/assets/9133227/89262b47-6119-4ec3-8e52-b8df41831fd4" width="40%">

Microk8s is a full embedded Kubernetes platform that is lightweight yet robust and scalable and is a perfect fit for edge, embedded scenarios.
KubeArmor support for Canonical MicroK8s as [a community addon](https://github.com/canonical/microk8s-community-addons/pull/147) is merged making microk8s more secure. Microk8s with KubeArmor brings enterprise grade security to lightweight edge kubernetes environments.

## Kind and Minikube Compatibility

With this release, KubeArmor extends its compatibility to Kind and Minikube clusters, enabling you to effortlessly apply KubeArmor's security policies to your local testing and development environments. Maintain consistency between testing and production while fortifying your workloads.

<img src="https://github.com/kubearmor/KubeArmor/assets/14152150/833b7bd2-dee9-4436-8c73-a0a4e2c09387" width="15%">
<img src="https://github.com/kubearmor/KubeArmor/assets/14152150/81269e2c-38cb-4a97-b898-b1f673eced52" width="35%">

## karmor profile

`karmor logs` tool provides raw telemetry out of the box. However, you may want to summarize the process, file, network, syscall events over a period of time. `karmor profile` introduces a way to handle the summarization. KubeArmor community followers might realize that the base `profile` feature was added in v0.8 release. v0.11 vastly improves the usability of the features, for e.g, by sorting the data based on process name, summarizing/aggregating well, adding syscall related event summarization etc.

![karmorprofile](https://github.com/kubearmor/KubeArmor/assets/23097199/f0aba5a0-7ef3-4ee3-88e6-4d4022031c67)



## EKS Addon published: Simplifing EKS deployment

<img src="https://github.com/kubearmor/KubeArmor/assets/9133227/bc17c1a7-507e-4d07-850a-6cc4f9247f5b" width="30%">

Amazon EKS Anywhere allows installing and managing Kubernetes clusters on your own infrastructure, with optional support from AWS. EKS Anywhere supports full lifecycle management of multiple Kubernetes clusters that can operate completely independently of any AWS services. It provides open-source software that’s up to date and patched so you can have an on-premises Kubernetes environment that’s more reliable than a self-managed Kubernetes offering. EKS Anywhere is compatible with Bare Metal, CloudStack, and VMware vSphere as deployment targets.

Although EKS Anywhere can make cluster administration easier, the issue of protecting how Kubernetes namespaces, pods, workloads, and clusters interaction and access of shared resources remains an unsolved problem. It is imperative that workloads are protected at runtime since most of the attacks such as cryptomining, ransomware, data exfiltration, denial of service are manifest once the workloads are deployed in target k8s environment.

In line with the recommended safety guidelines for EKS, KubeArmor comprehensively fulfills these requirements. Getting up to speed on the Kubernetes threat environment proves to be difficult for security teams. New responsibilities for Kubernetes infrastructure and workloads lead to high overhead. Furthermore, ensuring that platform and application teams have consistency and complete visibility across environments for configurations and settings to fulfill [AWS EKS security best practices](https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/aws/EKS/) can be difficult. KubeArmor helps you take care of most of these for you.

## Streamlined Deployment: Updated Helm Chart

Deploying KubeArmor has never been smoother. The updated Helm chart simplifies the installation process, ensuring that you can effortlessly manage KubeArmor's security policies across your Kubernetes clusters. Spend less time configuring and more time securing. Use of KubeArmor Operator greatly simplifies the auto detection of cluster components and deploying the kubearmor accordingly. For example, no more mounting of unwanted host mount points to just detect the container runtime in use.

## Staying in Sync with Infrastructure: Terraform Updates

For those who embrace infrastructure-as-code, KubeArmor v0.11 offers updated Terraform integration. Seamlessly incorporate KubeArmor into your Terraform workflows, ensuring consistent security provisioning throughout your infrastructure.

Open source [KubeArmor terraform provider from AccuKnox](https://github.com/accuknox/terraform-provider-accuknox#example---kubearmor-resources) helps provision KubeArmor deployments, policies, and configuration at scale using Hashicorp Terraform.

## Pushing Boundaries: Scale Testing with KubeArmor-Relay

Scalability is of paramount importance. One of primary hurdle to observability/monitoring solutions is its impact on runtime performance. With v0.11, we tested logging/telemetry components such as KubeArmor-Relay for scale of 100s of nodes. Through rigorous testing under varying workloads, KubeArmor v0.11 ensures unwavering performance even in the most dynamic Kubernetes environments.

## Flourishing Ecosystem: Adopters Update

Our [community of adopters](https://github.com/kubearmor/KubeArmor/blob/main/ADOPTERS.md) continues to grow, and we're immensely grateful for your support. Join a vibrant community of users and contributors who are shaping the future of container security. Together, we're elevating Kubernetes security to new heights.

## Thanks/Credits
We extend our gratitude to our dedicated community, whose feedback and contributions drive the evolution of KubeArmor. Dive into the cutting-edge security enhancements of KubeArmor v0.11 and fortify your Kubernetes environment with confidence.

To explore the latest features and embark on your journey with KubeArmor v0.11, visit our [official GitHub repository](https://github.com/kubearmor/kubearmor) and [comprehensive documentation](https://docs.kubearmor.io/kubearmor/).

Secure your containers, fortify your Kubernetes clusters — experience KubeArmor v0.11 today.

Stay secure,
The KubeArmor Team
