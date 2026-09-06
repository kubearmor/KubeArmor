# Security Policy
The Maintainers and contributors to KubeArmor take the security of our software seriously. 
The KubeArmor community has adopted the below security disclosures and response policy to promptly respond to critical issues.

Please do not report security vulnerabilities through public GitHub issues.

## Security bulletins
For information regarding the security of this project please join our [Slack channel](https://join.slack.com/t/kubearmor/shared_invite/zt-2bhlgoxw1-WTLMm_ica8PIhhNBNr2GfA).

## Reporting a Vulnerability
### When you should?
- You think you discovered a potential security vulnerability in KubeArmor.
- You are unsure how a vulnerability affects KubeArmor.
- You think you discovered a vulnerability in the dependency of KubeArmor. For those projects, please leverage their reporting policy.

### When you should not?
- You need assistance in configuring KubeArmor for security - please discuss this in the [Slack channel](https://cloud-native.slack.com/archives/C07EF44HWQM)
- You need help applying security-related updates.
- Your issue is not security-related.

### Private Reporting Process
To report a vulnerability privately, choose one of the following methods:
1. **GitHub Security Advisories (Recommended):** Submit a private vulnerability report directly through [GitHub Security Advisories](https://github.com/kubearmor/KubeArmor/security/advisories/new).
2. **Email Disclosure:** Email the **KubeArmor security team at `support@kubearmor.io`**.

Please include as much detail as possible to help us triage the report quickly:
- Type of issue (e.g. buffer overflow, privilege escalation, injection)
- Affected files, functions, tag/commit hash, or container image version
- Step-by-step instructions and proof-of-concept exploit script to reproduce
- Potential security impact and vector

### Response and Patch Timeline
- **Initial Acknowledgment:** 3-5 business days.
- **Triage & Vulnerability Fix:** Fixes are prepared and released within 7 to 28 days depending on severity and complexity.
- **Public Disclosure:** Security advisories and CVEs are published alongside the patch release.

## Verifying Release Artifacts and Container Images

KubeArmor cryptographically signs container images and release binaries using [Cosign](https://github.com/sigstore/cosign) and generates Level 3 build provenance with the [SLSA Framework](https://slsa.dev).

### 1. Verifying Container Images with Cosign
You can verify the signature of official KubeArmor container images using `cosign`:
```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/kubearmor/KubeArmor/\.github/workflows/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  kubearmor/kubearmor:<tag>
```

### 2. Verifying Release Binaries and Packages
Release binary packages (`.tar.gz`, `.deb`, `.rpm`) in [GitHub Releases](https://github.com/kubearmor/KubeArmor/releases) include signature (`.sig`) and certificate (`.pem`) bundles. Verify them using:
```bash
cosign verify-blob \
  --bundle <artifact>.sigstore.json \
  --certificate <artifact>.pem \
  --signature <artifact>.sig \
  --certificate-identity-regexp="https://github.com/kubearmor/KubeArmor/\.github/workflows/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <artifact>
```

### 3. Verifying SLSA Provenance
Verify SLSA build provenance using [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):
```bash
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/kubearmor/KubeArmor \
  <artifact>
```

## Security Audits and Automated Analysis

KubeArmor continuously monitors and audits code quality and security:
- **SAST & CodeQL:** Static security analysis runs on every pull request and weekly schedule ([`codeql.yml`](.github/workflows/codeql.yml)).
- **Vulnerability Scanning:** Container images and dependencies are scanned using Trivy ([`ci-trivy-scan.yaml`](.github/workflows/ci-trivy-scan.yaml)) and OSV.
- **Dependency Updates:** Automated dependency updates and digest pinning via Renovate.
- **Scorecard:** OpenSSF Scorecard supply-chain security monitoring ([`scorecard.yml`](.github/workflows/scorecard.yml)).

## Input Validation and Secure Design

KubeArmor enforces strict input validation across all entry points:
- **API & gRPC Validation:** All gRPC request payloads are validated against strict Protobuf definitions prior to execution.
- **Kubernetes CRDs:** Custom Resource Definitions (`KubeArmorPolicy`, `KubeArmorClusterPolicy`, `KubeArmorHostPolicy`) enforce strict OpenAPI v3 validation schemas and field allowlists.
- **Path & Parameter Sanitization:** System paths, container IDs, eBPF map parameters, and LSM security profile definitions are sanitized to prevent injection or privilege escalation vulnerabilities.

## Supported Versions
KubeArmor versions follow [Semantic Versioning](https://semver.org/) terminology (`x.y.z`):
- Security fixes are backported to the **latest two minor releases**.
- Patch releases are shipped periodically or as urgent security releases when required.
