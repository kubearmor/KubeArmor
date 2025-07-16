# ModelArmor: Securing Agentic AI and ML Models at Runtime

**ModelArmor** is a Zero Trust security solution purpose-built to protect AI/ML/LLM workloads from runtime threats. It safeguards against the unique risks of agentic AI systems and untrusted models by sandboxing deployments and enforcing granular runtime policies.

**ModelArmor** uses KubeArmor as a sandboxing engine to ensure that the untrusted models execution is constrained and within required checks. AI/ML Models are essentially processes and allowing untrusted models to execute in AI environments have significant risks such as possibility of cryptomining attacks leveraging GPUs, remote command injections, etc. KubeArmor's preemptive mitigation mechanism provides a suitable framework for constraining the execution environment of models.

ModelArmor can be used to enforce security policies on the model execution environment.

## Why ModelArmor?

ModelArmor enables secure deployment of **agentic AI applications** and **ML models**, addressing critical security gaps that traditional guardrails and static scanning cannot solve.

It is designed for:

- **Agentic AI workloads** using autonomous, tool-using agents.
- **ML pipelines** importing untrusted models from public repositories.
- Environments where **guardrails alone are not sufficient**.

ModelArmor protects the **entire AI lifecycle**, from development to deployment, using **sandboxing** and **policy enforcement** to neutralize malicious behavior at runtime.

## The Problem: Security Risks in Agentic AI

### 1. Arbitrary Code Execution

Agentic AI systems can **execute arbitrary system commands** due to their autonomy and access to tools.

- Prompt engineering can bypass LLM guardrails.
- Attackers can instruct agents to run harmful commands, download malware, or scan networks.

![](../../.gitbook/assets/modelarmor/demo1.png)

![](../../.gitbook/assets/modelarmor/demo2.png)

### 2. Model Supply Chain Attacks

Malicious models uploaded to public repositories (e.g., Hugging Face) can contain embedded payloads.

- Loading such models allows **hidden code execution**, leading to system compromise and C\&C communication.

![Code Execution Cannot Be Governed Traditionally](../../.gitbook/assets/modelarmor/risk1.png)

### 3. Prompt Injection Attacks

Crafted prompts can manipulate the agent into performing unauthorized actions:

- Reading sensitive files (e.g., `/root/.aws/credentials`).
- Installing tools (`apk add nmap`) or scanning networks.
- Fetching and executing external scripts.

> Traditional container security cannot detect these because they exploit application behavior, not the container itself.

![Guardrails are not enough against sophisticated prompt engineering](../../.gitbook/assets/modelarmor/risk2.png)

## The Solution

![](../../.gitbook/assets/modelarmor/issuesfixed.png)

### Sandboxing Agentic AI

ModelArmor **isolates agentic AI apps** and ML workloads at runtime, blocking unauthorized actions even if guardrails or code reviews are bypassed.

![Zero Trust Policy Enforcement](../../.gitbook/assets/modelarmor/use3.png)

### Zero Trust Policy Enforcement

Define **fine-grained security policies** to:

- **Restrict file system access** (e.g., block `/root/.aws/credentials`).
- **Control process execution** (allow only trusted binaries).
- **Limit network activity** (disable raw sockets, ICMP, or outbound traffic).

![](../../.gitbook/assets/modelarmor/use4.png)

### Automated Red Teaming

Simulate adversarial scenarios like malicious model imports and prompt injections to **identify vulnerabilities pre-deployment**.

### Protection Across the Stack

ModelArmor works across frameworks and environments:

- Supports any **language runtime** or **AI framework**.
- Requires no code changes to your application.
- Lightweight and **cost-efficient**, avoiding the overhead of MicroVMs or full isolation environments.

![Granular Policy Enforcement for Process, Network, Volumes and AI flows](../../.gitbook/assets/modelarmor/use5.png)

## TensorFlow Based Use Cases

### FGSM Adversarial Input Attack

An FGSM attack manipulates input data by adding imperceptible noise, creating adversarial examples that force the TensorFlow model to misclassify (e.g., predicting “5” for an image of “2”).

Traditional container security fails here because the model and container remain unchanged; the attack happens through crafted input.

**ModelArmor Protection:**

- Proactively simulates adversarial attacks using _Automated Red Teaming_.
- Secures model behavior with input validation and anomaly detection, akin to an _LLM Prompt Firewall_ for ML workloads.
- Protects against sophisticated input-level manipulations.

![](../../.gitbook/assets/modelarmor/use2.png)

[▶️ Watch FGSM Attack Video](https://drive.google.com/file/d/1EnmsIiR4G4bYmoxBIHTk1bDkW2XatM4N/preview)

### Keras Model Injection Attack

A deployed TensorFlow model in a Docker container is vulnerable to compromise via a malicious Keras Lambda layer. This attack involves:

- Installing Python inside the container or
- Copying malicious scripts (e.g., into `/tmp`) to execute unauthorized system commands.

**ModelArmor Protection:**

- Blocks unauthorized installations (e.g., Python) and filesystem modifications (e.g., writing to `/tmp`).
- Uses _Automated Red Teaming_ to detect such vulnerabilities pre-deployment.
- Isolates workloads (like TensorFlow) with _Sandboxing Agentic AI_ to prevent code injection.

![Keras Model Injection Attack Mitigation](../../.gitbook/assets/modelarmor/use1.png)

[▶️ Watch Keras Inject Video](https://drive.google.com/file/d/1olGBz3WUoJqmcAVdRY7uImKTHggRX6nK/preview)

---

## Securing NVIDIA NIM

![](../../.gitbook/assets/modelarmor/nvidia1.png)

![](../../.gitbook/assets/modelarmor/nvidia2.png)

📄 [View PDF: Securing_NVIDIA_NIM.pdf](https://drive.google.com/file/d/16DjsSyOAWr1S4EwSTBSx63SLDHPFnSAh/preview)
