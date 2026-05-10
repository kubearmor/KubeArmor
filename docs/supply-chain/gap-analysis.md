# KubeArmor Supply Chain Security — Gap Analysis

**Date**: May 2026
**Scope**: SLSA Level 3 compliance and OpenSSF Scorecard hardening
**Issue**: [#2566](https://github.com/kubearmor/KubeArmor/issues/2566)

---

## Executive Summary

KubeArmor's release pipeline is already significantly hardened. GoReleaser
produces signed release artifacts (`.sigstore.json` bundles) for every release,
giving a live Scorecard `Signed-Releases` score of **8/10**. The cached badge
(api.scorecard.dev) shows a stale value and will update on the next weekly scan.

This document identifies the remaining gaps and the concrete steps to reach
full SLSA Level 3 compliance.

---

## Current State (Baseline Measurement)

### OpenSSF Scorecard — Live CLI Results

```
Signed-Releases : 8 / 10
Reason: 5 out of 5 release artifacts are signed (via GoReleaser + cosign)
Gap: No SLSA provenance (.intoto.jsonl) found on any release
```

### Existing Signing Infrastructure

| Component               | Status     | Evidence                                                         |
| ----------------------- | ---------- | ---------------------------------------------------------------- |
| Binary artifacts signed | ✅ Done    | `.sigstore.json` on every release (v1.6.14+)                     |
| Container images signed | ✅ Done    | cosign in `ci-latest-release.yml` and `ci-operator-release.yaml` |
| SBOM generation         | ❌ Missing | No `.sbom.json` files on releases                                |
| SLSA provenance         | ❌ Missing | No `.intoto.jsonl` on any release                                |
| Scorecard CI tracking   | ⚠️ Partial | `scorecard.yml` exists but uses outdated action versions         |

### cosign Verification of Existing Artifacts

The following command verifies the EXISTING signing on the latest release (no
changes needed — GoReleaser already does this):

```bash
VERSION="1.6.18"
ARCH="amd64"

curl -LO https://github.com/kubearmor/KubeArmor/releases/download/v${VERSION}/kubearmor_${VERSION}_linux-${ARCH}.tar.gz
curl -LO https://github.com/kubearmor/KubeArmor/releases/download/v${VERSION}/kubearmor_${VERSION}_linux-${ARCH}.tar.gz.sigstore.json

cosign verify-blob \
  kubearmor_${VERSION}_linux-${ARCH}.tar.gz \
  --bundle kubearmor_${VERSION}_linux-${ARCH}.tar.gz.sigstore.json \
  --certificate-identity-regexp "https://github.com/kubearmor/KubeArmor/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Output: Verified OK
```

---

## Gap Analysis — SLSA Level 3 Requirements

Reference: https://slsa.dev/spec/v0.1/requirements

### Build Requirements

| Requirement             | Status | Gap                            | Fix                                                   |
| ----------------------- | ------ | ------------------------------ | ----------------------------------------------------- |
| Scripted build          | ✅     | —                              | GoReleaser handles all builds                         |
| Build service           | ✅     | —                              | GitHub Actions (hosted)                               |
| Build as code           | ✅     | —                              | `.goreleaser.yaml` in source                          |
| Ephemeral environment   | ✅     | —                              | GitHub Actions runners are ephemeral                  |
| Isolated build          | ✅     | —                              | Each runner is isolated                               |
| Parameterless top-level | ⚠️     | Release triggers accept inputs | Remove workflow_dispatch inputs from release workflow |

### Source Requirements

| Requirement           | Status | Gap                         | Fix                             |
| --------------------- | ------ | --------------------------- | ------------------------------- |
| Version controlled    | ✅     | —                           | GitHub                          |
| Verified history      | ✅     | —                           | GitHub maintains commit history |
| Retained indefinitely | ✅     | —                           | GitHub                          |
| Two-person reviewed   | ⚠️     | PRs need 2 reviews enforced | Enable branch protection rules  |

### Provenance Requirements

| Requirement                      | Status | Gap                            | Fix                                                                  |
| -------------------------------- | ------ | ------------------------------ | -------------------------------------------------------------------- |
| Provenance generated             | ❌     | No `.intoto.jsonl` on releases | Add `slsa-github-generator` workflow                                 |
| Provenance authenticated         | ❌     | No provenance to authenticate  | Follows from above                                                   |
| Provenance service generated     | ❌     | —                              | Follows from above                                                   |
| Provenance non-falsifiable       | ❌     | —                              | `slsa-github-generator` achieves this via isolated reusable workflow |
| Provenance dependencies complete | ❌     | —                              | Follows from above                                                   |

### Common Requirements

| Requirement | Status | Gap                        | Fix                          |
| ----------- | ------ | -------------------------- | ---------------------------- |
| Security    | ✅     | —                          | SECURITY.md exists           |
| Access      | ✅     | —                          | Branch protection in place   |
| Superusers  | ⚠️     | Admin access not minimized | Review org admin permissions |

---

## Gap Analysis — OpenSSF Scorecard Checks

Current scores and gaps (live CLI scan, May 2026):

| Check               | Score   | Gap                                           | Priority                          |
| ------------------- | ------- | --------------------------------------------- | --------------------------------- |
| Signed-Releases     | 8/10    | No SLSA provenance (`.intoto.jsonl`)          | 🔴 High — This PR                 |
| Pinned-Dependencies | Low     | Many actions use tag refs, not SHA            | 🔴 High — This PR (scorecard.yml) |
| Token-Permissions   | Low     | Workflows lack explicit job-level permissions | 🔴 High — This PR                 |
| Fuzzing             | 0/10    | No OSS-Fuzz integration                       | 🟡 Medium — Follow-up             |
| SAST                | Low     | CodeQL not configured                         | 🟡 Medium — Follow-up             |
| CII-Best-Practices  | Partial | Badge exists but may need update              | 🟢 Low — Follow-up                |
| Branch-Protection   | Unknown | Review current settings                       | 🟡 Medium — Follow-up             |

---

## What This PR Fixes

1. **Signed-Releases 8/10 → 10/10**: Adds `slsa-provenance.yml` workflow using
   `slsa-github-generator` to produce `.intoto.jsonl` on every release.

2. **Pinned-Dependencies**: Updates `scorecard.yml` to pin all 4 actions by SHA.

3. **Token-Permissions**: Adds job-level minimum permissions to `scorecard.yml`.

4. **Documentation**: This gap analysis document (required by issue #2566).

---

## Follow-Up Issues (for Mentorship Term)

The following issues should be created for the main mentorship work:

| Issue Title                                         | Check Addressed     | Priority |
| --------------------------------------------------- | ------------------- | -------- |
| Enable OSS-Fuzz integration for KubeArmor           | Fuzzing             | High     |
| Add CodeQL SAST workflow                            | SAST                | High     |
| Pin all workflow action dependencies by SHA         | Pinned-Dependencies | High     |
| Add SLSA provenance to container image releases     | Signed-Releases     | Medium   |
| Enable branch protection: require 2 reviews on main | Branch-Protection   | Medium   |
| Review and minimize org admin permissions           | Security            | Low      |

---

## Verification Instructions

After merging this PR and on the next tagged release, verify end-to-end:

```bash
# Install verification tools
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Run the verification script (included in this PR)
./scripts/verify-release-artifacts.sh v1.6.19

# Or manually:
VERSION="1.6.19"
ARCH="amd64"
ARTIFACT="kubearmor_${VERSION}_linux-${ARCH}.tar.gz"

# Verify cosign signature (existing)
cosign verify-blob "${ARTIFACT}" \
  --bundle "${ARTIFACT}.sigstore.json" \
  --certificate-identity-regexp "https://github.com/kubearmor/KubeArmor/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify SLSA provenance (new, from this PR)
slsa-verifier verify-artifact "${ARTIFACT}" \
  --provenance-path kubearmor.intoto.jsonl \
  --source-uri github.com/kubearmor/KubeArmor \
  --source-tag "v${VERSION}"
```

---

## References

- [SLSA Framework v0.1 Requirements](https://slsa.dev/spec/v0.1/requirements)
- [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
- [KubeEdge SLSA L3 Journey](https://kubeedge.io/blog/reach-slsa-l3/) (prior art)
- [OpenSSF Scorecard Checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [Sigstore Cosign](https://github.com/sigstore/cosign)
- [Issue #2566](https://github.com/kubearmor/KubeArmor/issues/2566) — LFX Mentorship
- [Issue #1164](https://github.com/kubearmor/KubeArmor/issues/1164) — Original SLSA request
