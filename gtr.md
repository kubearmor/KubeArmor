# General Technical Review - KubeArmor / Incubation

-   **Project:**  KubeArmor
-   **Project Version:**  v1.7.4
-   **Website:**  [https://kubearmor.io](https://kubearmor.io/)
-   **Date Updated:**  2026-07-017
-   **Template Version:**  v1.0
-   **Description:**  KubeArmor is a cloud native runtime security enforcement engine that uses eBPF and Linux Security Modules (AppArmor, BPF-LSM, SELinux) to preemptively restrict process execution, file access, network operations, and capability use inside containers, pods, VMs, and bare-metal hosts, based on Kubernetes-native policy CRDs.

## Day 0 - Planning Phase

### Scope
* Describe the roadmap process, how scope is determined for mid to long term features, as well as how the roadmap maps back to current contributions and maintainer ladder?

New features, bugs, and proposals enter as GitHub issues and are triaged onto the public  [KubeArmor Projects board](https://github.com/orgs/kubearmor/projects/9)  by any Maintainer.
Significant features require a written proposal (a GitHub Wiki  or a GitHub Discussion) and acceptance by Maintainer ordinary vote before implementation begins.
Routine bug fixes and small enhancements follow the standard pull-request flow with lazy consensus (see  [GOVERNANCE.md § Roadmap and contribution acceptance](https://github.com/kubearmor/KubeArmor/blob/main/GOVERNANCE.md#roadmap-and-contribution-acceptance)).
  * Describe the target persona or user(s) for the project?

DevSecOps and Security teams operating Kubernetes clusters, Linux Host machines, IoT devices, and 5G control planes who need to harden workloads at runtime without hand-authoring AppArmor/SELinux profiles. See the [KubeArmor differentiation guide](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/differentiation.md) and the [IoT/Edge](https://open-horizon.github.io/docs/kubearmor-integration/docs/README/) and [5G](https://5gsec.com/) use cases on [kubearmor.io](https://kubearmor.io/).

  * Explain the primary use case for the project. What additional use cases are supported by the project?

**Primary:**  
Preemptive, inline runtime enforcement of least-permissive ("Zero Trust") security policy for Kubernetes pods and nodes by denying a disallowed process/file/network/capability action before it completes, rather than detecting and reacting afterward ([Least Permissive Access](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/least_permissive_access.md)).
**Additional supported use cases:** 
Out-of-the-box workload hardening mapped to CIS/MITRE/NIST-800-53/STIGs ([Hardening Guide](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/hardening_guide.md))
Network visibility and auto-generated Kubernetes NetworkPolicy for micro-segmentation ([Network Segmentation](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/network_segmentation.md))
Application/process/file/network behavior visibility independent of enforcement ([Workload Visibility](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/workload_visibility.md))
Protection of non-containerized VM/bare-metal workloads in systemd mode ([Support Matrix](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/support_matrix.md)
AI/ML model and inference workload protection via the  [ModelArmor](https://docs.kubearmor.io/kubearmor/use-cases/modelarmor)  use case.

  * Explain which use cases have been identified as unsupported by the project.  

* KubeArmor is not a general-purpose policy engine (such as OPA) or a CNI.
* KubeArmor does not intend to be a resource utilization tracking solution. For e.g., the amount of CPU/memory used by the workloads.
* KubeArmor does not intend to be a debugging tool, such as for system call tracing or object-level action tracing, even though there have been instances where the tool was used in the context to check if a particular process is indeed modifying the given file or not.

  * Describe the intended types of organizations who would benefit from adopting this project. (i.e. financial services, any software manufacturer, organizations providing platform engineering services)?  

Any organization running containerized/Kubernetes, Linux server, or IoT workloads with a Zero Trust or hardening mandate: 
Regulated industries pursuing CIS/NIST/STIG-aligned hardening across Linux server fleets (e.g. financial services, government).
Telecom operators securing 5G control-plane workloads, edge/IoT.
Deployers securing embedded and connected devices (Open Horizon, Intel Smart Edge, IDSM Automotive)
Platform engineering teams building a security "golden path" for internal Kubernetes and Linux infrastructure users.

  * Please describe any completed end user research and link to any reports.
N/A

### Usability

  * How should the target personas interact with your project?

Primarily through Kubernetes-native CRDs (`kubectl apply -f policy.yaml`) and the `karmor` CLI, which is used to install KubeArmor, probe platform support, stream logs/alerts, and auto-generate recommended hardening policies (`karmor recommend`) or discovered network policies (`karmor discover`).
There is no dedicated project-maintained GUI

  * Describe the user experience (UX) and user interface (UI) of the project.  
For Kubernetes users, the user experience is very much k8s native:
1. Onboarding: The onboarding of kubearmor happens using kubernetes operator. The configuration used for the installation is available as part of the config map.
2. Policy Creation/Apply: K8s native resource definitions are available for policies. K8s native tools can be used to enlist, edit, track these policies.
3. Policy Violations: KubeArmor provides a relay service that aggregates policy violations/telemetry across all the nodes in the k8s env. The karmor cli tool helps provides a way to filter, access the telemetry or violations in a live environment.

For non-kubernetes users:
1. Onboarding: The onboarding is handled using systemd services in Linux.
2. Policy creation/apply: The policy structure for k8s and non-k8s env are same except for the change in the selector options. The policy is applied using karmor cli tool.
3. Policy Violations: Policy violations can be observed in exactly the same way as it is done in the context of k8s env using karmor cli tool. 


  * Describe how this project integrates with other projects in a production environment.

The following are the different ways:
1. Other projects can listen to the telemetry that is emitted by KubeArmor and operate on it. For e.g., if a particular file is opened, then take an action.
2. Projects can listen to the policy violations and then use the alert as an IoC (Indicator of Compromise) to further handle the investigation. KubeArmor telemetry before and after the policy violation can be used for triaging along with other log/telemetry sources. Projects integrate with Threat Intelligence sources such as MISP, AlienVault, VirusTotal, etc to further check the possibility of a compromise.
3. Metrics, Telemetry, and violations can be handled by other projects and used for application-specific actions.

### Design

  * Explain the design principles and best practices the project is following.

KubeArmor is built around few core ideas:
**Pre-emptive Mitigation** KubeArmor has ensured that it does not deviate from its stance of doing pre-emptive mitigation, i.e., using primitives such as LSM (Linux Security Modules) to prevent a malicious action, rather than detecting and then sending a kill signal or any other post-attack remedial action. Our thesis has been that, "If you allow the attacker to execute their code in the target environment, however briefly, one cannot recover from that state."
**Deny by default, allow what you trust.** Policies work on a "least privilege" / Zero Trust model . Nothing is permitted unless you explicitly say so, this flips the usual mindset from "block the bad stuff" to "only allow what you know is good," which is a much safer default.
**You shouldn't need to be a kernel security expert.** Writing raw AppArmor or SELinux profiles by hand is tedious and error-prone, especially when every cloud provider defaults to a different LSM under the hood. KubeArmor abstracts that away, you write one policy  and we handle the translation to whatever's running on the node.
**Nothing about your workloads needs to change.** No rebuilding images, no editing pod specs. Enforcement gets injected automatically through a mutating webhook and/or a node-level agent, so your existing deployments just work.

  * Outline or link to the project’s architecture requirements? Describe how they differ for Proof of Concept, Development, Test and Production environments, as applicable.

KubeArmor only requires a running Kubernetes cluster with a supported LSM enabled. There is no different requirement for PoC/Dev/Test & Prod.

  * Define any specific service dependencies the project relies on in the cluster.  
N/A
  * Describe how the project implements Identity and Access Management.  
KubeArmor creates service accounts for itself to modify certain cluster wide resources such as KubeArmor policies. The access management is least-permissive, it only requests for the specific API accesses that are needed to handle its task.
  * Describe how the project has addressed sovereignty.  
KubeArmor or any of the other associated projects never sends any beacon message or telemetry to any outside system. KubeArmor can easily operate even in air-gapped environments.
  * Describe any compliance requirements addressed by the project.  
KubeArmor helps enforce CIS benchmarks. For e.g., one of the CIS benchmark is to set the `/tmp` in noexec mode such that only read/write is possible but process executions are not possible from `/tmp` folder. The CIS benchmarks remediation requires one to create a separate mount point for `/tmp` and set the `noexec` attribute in the context. This approach is not possible in the context of containerized or k8s orchestrated workloads since creating a separate mount point for every container/pod is impossible. KubeArmor helps achieve fulfillment of such CIS benchmarks by creating a policy that sets the `/tmp` folder in R/W mode but no executions would be allowed.
  * Describe the project’s High Availability requirements.  
KubeArmor leverages K8s native design for high availability.
1. KubeArmor Daemonset: The daemonset is k8s construct. If the daemonset pod on the node goes down, the k8s control plane ensures to bring it up.
2. KubeArmor Relay/Controller: K8s replicasets are used for high availability.
  * Describe the project’s resource requirements, including CPU, Network and Memory.  

Resource-wise, the DaemonSet, Controller, and Relay each request a modest `10m` CPU / `64Mi` memory to run.
In terms of actual runtime overhead:
**CPU impact is minimal.** With the default setup (Process and Network visibility enabled plus policy enforcement) the CPU overhead is under 3%.
**Memory depends on your LSM.** BPF-LSM adds roughly 250MB, while AppArmor stays under 100MB.
**Network**: KubeArmor does not require network to operate.

  * Describe the project’s storage requirements, including its use of ephemeral and/or persistent storage.  
In Kubernetes mode of installation, Kubearmor does not require any persistant storage while requiring an ephemeral storage used by the init container to compile and pass the bpf compiled objects to the main container for loading to the kernel.
In host mode of installation, KubeArmor will persist rules, logs and other required informations under `/opt/KubeArmor/` directory

* Please outline the project’s API Design.
KubeArmor doesn't expose any REST APIs, instead, it uses gRPC to provide core functionality like log watching, policy enforcement, and health checks. These functions change infrequently since we aim to keep them as generic as possible. When a change is unavoidable, we add a new function, mark the old one as deprecated, and remove it only after it has aged out of the support window.

For Policy creation/updates, k8s native resource model is used for managing the policies.

  * Describe the project’s release processes, including major, minor and patch releases.

Semantic Versioning 2.0 with monthly release cadence; every MINOR (and most PATCH) releases go through at least one release-candidate stage kept open for a minimum of one calendar week, ad-hoc releases are cut for critical bugs/security issues and may skip the RC stage for small, well-isolated fixes. 
Each release is tracked by a public release-checklist GitHub issue (e.g. [#2704](https://github.com/kubearmor/KubeArmor/issues/2704)); releases are coordinated with the [`charts`](https://github.com/kubearmor/charts) and [`kubearmor-client`](https://github.com/kubearmor/kubearmor-client) repositories; the latest two MINOR releases are supported with backports. Full detail in [RELEASES.md](https://github.com/kubearmor/KubeArmor/blob/main/RELEASES.md).

### Installation

  * Describe how the project is installed and initialized, e.g. a minimal install with a few lines of code or does it require more complex integration and configuration?  
A minimal, three-command Helm install:
```
helm repo add kubearmor https://kubearmor.github.io/charts
helm upgrade --install kubearmor-operator kubearmor/kubearmor-operator -n kubearmor --create-namespace
kubectl apply -f https://raw.githubusercontent.com/kubearmor/KubeArmor/main/pkg/KubeArmorOperator/config/samples/sample-config.yml

```
The Operator then deploys the DaemonSet, Relay, and Controller, auto-detecting the node environment (GKE/EKS/BottleRocket/k0s/k3s/microk8s/generic) to select the correct volume mounts and CRI socket path. The optional `karmor` CLI installs via a single curl script. For non-Kubernetes workloads, KubeArmor installs in systemd mode on VMs/bare metal (see [Support Matrix](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/support_matrix.md)).

  * How does an adopter test and validate the installation?
`karmor probe` reports whether the platform is supported and which LSM is active (a blank "Active LSM" means enforcement will not work, only observability).
The [Deployment Guide](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/deployment_guide.md) walks through deploying a test nginx pod, applying a sample `Block` policy, and confirming both the runtime denial and the corresponding `karmor logs` event.

### Security
  * Please provide a link to the project’s cloud native [security self assessment](https://tag-security.cncf.io/community/assessments/).  
WIP

  * Please review the [Cloud Native Security Tenets](https://github.com/cncf/contribute-site/blob/main/docs/community/tags/security-and-compliance/publications/secure-defaults-cloud-native-8.md) from TAG Security.  
    * How are you satisfying the tenets of cloud native security projects?
**1. Security as a design requirement**  
KubeArmor is a runtime security enforcement engine from the ground up, not security bolted onto an existing system. It's built specifically around least-permissive/zero-trust enforcement for process, file, and network restriction.
**2. Secure configuration has the best UX**  
The `karmor recommend` CLI generates ready-to-apply `KubeArmorPolicy`/`KubeArmorHostPolicy` YAML tailored to a workload's actual context (base image, MITRE/CIS/STIG mappings), so hardening is a `kubectl apply` away rather than something operators write from scratch.
**3. Insecure configuration is a conscious choice**  
Policies default to visibility/audit mode unless a rule explicitly sets `action: Block`, so blocking (the more disruptive, "insecure-to-turn-off" path) requires an explicit, visible declaration in the policy spec rather than being silently assumed.
**4. Transition from insecure to secure is possible**  
Because policies are applied incrementally per label/namespace, and KubeArmor supports an audit-only mode before enforcement, teams can observe violations first, tune policy, then flip to blocking a gradual, reversible path rather than a hard cutover.
**5. Secure defaults are inherited**  
KubeArmor doesn't reimplement enforcement, it inherits the security guarantees of the underlying Linux LSM stack (AppArmor/SELinux/BPF-LSM) and eBPF, layering container/pod identity on top rather than replacing kernel-level controls.
**6. Exception lists have first-class support**  
The policy CRDs support explicit allow/exception rules (e.g., `fromSource`, matching specific binaries/paths) so th	t restrictive defaults can be scoped down without abandoning enforcement elsewhere.
**7. Protection against pervasive exploits**  
Runtime restrictions on process execution, file access, and network behavior directly blunt common exploit chains (RCE → arbitrary exec, privilege escalation, unauthorized file/credential access) this is the core value proposition, not an add-on.
**8. Security limitations are explainable**  
KubeArmor depends on host LSM support, the docs are explicit about what's enforceable per kernel/OS (e.g., BPF-LSM vs AppArmor), so gaps are documented rather than silently assumed.
* Security Hygiene
	* Please describe the frameworks, practices and procedures the project uses to maintain the basic health and security of the project. 
All changes to KubeArmor go through pull requests with mandatory reviews and CI checks (build, unit tests, and e2e tests) before merging to `main`. We don't merge on green CI alone, every enforcement-path change gets a human review from a maintainer familiar with the LSM/eBPF internals.
	* Describe how the project has evaluated which features will be a security risk to users if they are not maintained by the project?
We weigh attack surface against maintenance commitment. The core/community split is our main lever: anything on the enforcement path is core, since a lapse there means policies silently stop enforcing.
  * Cloud Native Threat Modeling  
    * Explain the least minimal privileges required by the project and reasons for additional privileges.
KubeArmor runs as a DaemonSet needing host access to hook LSMs (AppArmor/BPF-LSM) and eBPF for  enforcement to works. We need host PID/mount visibility to map syscalls to container identities, access to `/sys/kernel/security` for LSM policy loading, and BPF capabilities for the eBPF monitor. We avoid blanket `privileged: true` where possible, scoping to just what LSM/eBPF hooking needs.
    * Describe how the project is handling certificate rotation and mitigates any issues with certificates.  
Certs are issued and rotated through our deployment tooling (Helm/operator) rather than as static long-lived secrets and we're moving toward letting standard cluster cert tooling (e.g., cert-manager) own rotation where users already have it installed instead of reinventing cert lifecycle management ourselves.
    * Describe how the project is following and implementing [secure software supply chain best practices](https://project.linuxfoundation.org/hubfs/CNCF\_SSCP\_v1.pdf) 
Broken link.

## Day 1 \- Installation and Deployment Phase
### Project Installation and Configuration
  * Describe what project installation and configuration look like.
**Installation**
KubeArmor installs via Helm chart or the KubeArmor Operator (recommended) or with `karmor install` from the CLI for quick setup. It deploys as a DaemonSet across nodes, plus a relay and and an operator controller with an admission webhook. It auto-detects the best available enforcement backend (BPF-LSM or AppArmor) per node.
**Configuration**
Security policies are applied as native Kubernetes CRDs targeted via label selectors like any other k8s resource. As a starting point, `karmor recommend` generates ready-to-apply hardening policies based on the workload's base image and MITRE/CIS/STIG mappings instead of writing rules from scratch.
### Project Enablement and Rollback
  * How can this project be enabled or disabled in a live cluster? Please describe any downtime required of the control plane or nodes.  
**Enabling**
KubeArmor can be installed using any installation method mentioned in the above section
**Disabling**
KubeArmor can be removed by either removing the operator and its related CRD or by running `helm uninstall` or by using `karmor uninstall`.
**Downtime**
Enabling or Disabling kubearmor does not require any down time generally. The only exception to this rule is when the administrator is enabling bpf-lsm, in this case a restart is required.
  * Describe how enabling the project changes any default behavior of the cluster or running workloads.  
N/A
  * Describe how the project tests enablement and disablement.
Running e2e tests is a core concept of our CI/CD pipelines to ensure that kubearmor can be installed on various systems.
  * How does the project clean up any resources created, including CRDs?
Resources are deleted automatically when following any method mentioned in the above section "Disabling". CRD's can be deleted using `karmor uninstall --force`
### Rollout, Upgrade and Rollback Planning
  * How does the project intend to provide and maintain compatibility with infrastructure and orchestration management tools like Kubernetes and with what frequency?  
We test kubearmor in our CICD for compatibility with Kubernetes and in addition we test against various flavors of Kubernetes as part of our release process.
  * Describe how the project handles rollback procedures.  
Rollbacks can be handled using the standard `helm rollback` or by reverting the changes in the `kubearmorconfig` crd or by re-running `karmor install` with the old flags.
  * How can a rollout or rollback fail? Describe any impact to already running workloads.  
If a rollback fails, the nodes with the failed pods will loose policy enforcement and visibility till the rollback issue is handled.
  * Describe any specific metrics that should inform a rollback.
 N/A
  * Explain how upgrades and rollbacks were tested and how the upgrade-\>downgrade-\>upgrade path was tested.
N/A  
  * Explain how the project informs users of deprecations and removals of features and APIs.  
N/A
  * Explain how the project permits utilization of alpha and beta capabilities as part of a rollout.
N/A
