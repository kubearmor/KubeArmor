# KubeArmor Supply Chain Security

This document describes how KubeArmor signs its release artifacts, how consumers can verify those signatures, and the current OpenSSF Scorecard posture.

## What is signed

Every tagged release of KubeArmor produces the following signed artifacts:

| Artifact type | Signed? | Method |
|---|---|---|
| `.tar.gz` archives (systemd binaries) | Yes | cosign keyless attest-blob, DSSE envelope in `.sigstore.json` |
| `.deb` packages | Yes | cosign keyless attest-blob, DSSE envelope in `.sigstore.json` |
| `.rpm` packages | Yes | cosign keyless attest-blob, DSSE envelope in `.sigstore.json` |
| Checksum files | Yes | cosign keyless attest-blob, DSSE envelope in `.sigstore.json` |
| SBOM (`.sbom.spdx.json`) | Yes | cosign keyless attest-blob, DSSE envelope in `.sigstore.json` |
| Combined provenance | Yes | `multiple-linux-{arch}.intoto.jsonl` uploaded to GitHub Release |
| Container images | Yes | cosign keyless, stored in registry transparency log |
| SLSA provenance | Yes | SLSA Level 3 via `slsa-github-generator` |
| GitHub native attestations | Yes | `actions/attest-build-provenance` |

Signing uses [Sigstore](https://www.sigstore.dev/) keyless signing — no long-lived private keys are stored. The signing identity is the GitHub Actions OIDC token issued to the release workflow.

---

## Verifying signed release binaries

Release binaries are signed using `cosign attest-blob`, which produces a DSSE envelope (in-toto statement) inside each `.sigstore.json` bundle. This format allows the OpenSSF Scorecard Signed-Releases check to score 10/10.

Download the artifact and its bundle from the GitHub release page, then run:

```bash
cosign verify-blob-attestation \
  --bundle kubearmor_<VERSION>_linux-amd64.tar.gz.sigstore.json \
  --type slsaprovenance \
  --certificate-identity-regexp \
    "https://github.com/kubearmor/KubeArmor/.github/workflows/ci-systemd-release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  kubearmor_<VERSION>_linux-amd64.tar.gz
```

Replace `<VERSION>` with the release tag (e.g. `1.7.1`). The same command works for `.deb`, `.rpm`, and checksum files by swapping the filename.

**Example — download and verify v1.7.1:**

```bash
VERSION=1.7.1
BASE="https://github.com/kubearmor/KubeArmor/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/kubearmor_${VERSION}_linux-amd64.tar.gz"
curl -fsSLO "${BASE}/kubearmor_${VERSION}_linux-amd64.tar.gz.sigstore.json"

cosign verify-blob-attestation \
  --bundle "kubearmor_${VERSION}_linux-amd64.tar.gz.sigstore.json" \
  --type slsaprovenance \
  --certificate-identity-regexp \
    "https://github.com/kubearmor/KubeArmor/.github/workflows/ci-systemd-release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "kubearmor_${VERSION}_linux-amd64.tar.gz"
```

A successful verification prints `Verified OK`.

---

## Verifying signed container images

KubeArmor container images are published to Docker Hub and signed with cosign keyless signing in the CI/CD pipeline.

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/kubearmor/KubeArmor/.github/workflows/ci-latest-release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  docker.io/kubearmor/kubearmor:<TAG>
```

Signed images include:
- `kubearmor/kubearmor:<tag>`
- `kubearmor/kubearmor-init:<tag>`
- `kubearmor/kubearmor-controller:<tag>`
- `kubearmor/kubearmor-operator:<tag>`
- `kubearmor/kubearmor-snitch:<tag>`

**Example — verify the latest image:**

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/kubearmor/KubeArmor/.github/workflows/ci-latest-release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  docker.io/kubearmor/kubearmor:latest
```

---

## Verifying SLSA provenance

SLSA Level 3 provenance is generated for every tagged release using [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator). The provenance file (`.intoto.jsonl`) is uploaded to the GitHub release.

Install the [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) and run:

```bash
VERSION=1.7.1

# Download the artifact, provenance, and signature bundle
gh release download "v${VERSION}" \
  --repo kubearmor/KubeArmor \
  --pattern "kubearmor_${VERSION}_linux-amd64.tar.gz" \
  --pattern "*.intoto.jsonl" \
  --dir ./dist

slsa-verifier verify-artifact "dist/kubearmor_${VERSION}_linux-amd64.tar.gz" \
  --provenance-path dist/*.intoto.jsonl \
  --source-uri "github.com/kubearmor/KubeArmor" \
  --source-tag "v${VERSION}"
```

---

## Verifying SBOM signatures

Starting with releases that include SBOM files (`*.sbom.spdx.json`), the SBOM itself is also signed:

```bash
cosign verify-blob \
  --bundle "kubearmor_${VERSION}_linux-amd64.tar.gz.sbom.spdx.json.sigstore.json" \
  --certificate-identity-regexp \
    "https://github.com/kubearmor/KubeArmor/.github/workflows/ci-systemd-release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "kubearmor_${VERSION}_linux-amd64.tar.gz.sbom.spdx.json"
```

---

## OpenSSF Scorecard baseline

KubeArmor is tracked on [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/kubearmor/KubeArmor).

**Baseline snapshot (2026-05-17, aggregate 6.3/10):**

| Check | Score | Notes |
|---|---|---|
| Binary-Artifacts | 0/10 | Some pre-compiled binaries present in repo tree |
| Branch-Protection | 1/10 | Branch protection not maximal on all release branches |
| CI-Tests | 10/10 | All merged PRs checked by CI |
| CII-Best-Practices | 5/10 | OpenSSF Best Practices badge: passing |
| Code-Review | 10/10 | All changesets reviewed |
| Contributors | 10/10 | 30+ organisations contributing |
| Dangerous-Workflow | 10/10 | No dangerous workflow patterns |
| Dependency-Update-Tool | 10/10 | Dependabot / Renovate detected |
| Fuzzing | 10/10 | Project is fuzzed |
| License | 10/10 | Apache-2.0 detected |
| Maintained | 10/10 | Active commits and issues |
| Packaging | 10/10 | Publishing workflow detected |
| Pinned-Dependencies | 0/10 | Several GitHub Actions used floating tags |
| SAST | 10/10 | CodeQL runs on all commits |
| Security-Policy | 10/10 | SECURITY.md present |
| **Signed-Releases** | **0/10** | Stale cached result — `.sigstore.json` bundles ARE present in releases; score will update on next weekly scan |
| Token-Permissions | 0/10 | Some workflow tokens have write permissions not scoped to specific needs |
| Vulnerabilities | 5/10 | 5 existing CVEs in dependencies |

### What this PR improves

| Check | Before | After |
|---|---|---|
| Pinned-Dependencies | 0/10 | Improved — all release workflow actions SHA-pinned |
| Signed-Releases | 0/10 | Stable — signing already in place; SBOM signing added |

**Checks addressed by this PR:**
- `ci-latest-release.yml`: All `uses:` directives pinned to commit SHA
- `ci-operator-release.yaml`: All `uses:` directives pinned to commit SHA
- `ci-stable-release.yml`: All `uses:` directives pinned to commit SHA
- `ci-systemd-release.yml`: Added `attestations: write` permission and `actions/attest-build-provenance` step; all SHAs pinned
- `KubeArmor/.goreleaser.yaml`: SBOM generation added; SBOM is also signed by the existing `signs` block

### Remaining gaps (not in scope for this PR)

- **Binary-Artifacts**: Pre-compiled object files checked into the repo source tree should be removed or generated at build time.
- **Branch-Protection**: Requires admin-level GitHub settings changes.
- **Token-Permissions**: Individual workflow jobs need scoped permission blocks; tracked separately.

---

## Tools used

| Tool | Purpose |
|---|---|
| [cosign](https://github.com/sigstore/cosign) v2+ | Keyless signing and verification of blobs and images |
| [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) | SLSA provenance verification |
| [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) | SLSA Level 3 provenance generation in CI |
| [GoReleaser](https://goreleaser.com/) | Builds, packages, and signs binary release artifacts |
| [scorecard](https://github.com/ossf/scorecard) | OpenSSF supply-chain risk scoring |
