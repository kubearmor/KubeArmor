# KubeArmor Release Process

This document describes how KubeArmor releases are planned, prepared, tested, and shipped. It applies to the main [KubeArmor](https://github.com/kubearmor/KubeArmor) repository. Related repositories under the [kubearmor](https://github.com/kubearmor) organization are released alongside the main repository as described in the [Coordinated releases](#coordinated-releases) section below.

For the higher-level project governance, see [GOVERNANCE.md](./GOVERNANCE.md). For reporting security issues, see [SECURITY.md](./SECURITY.md).

## Versioning

KubeArmor uses [Semantic Versioning 2.0.0](https://semver.org/) — `MAJOR.MINOR.PATCH`:

- **MAJOR** increments on breaking API or policy-spec changes.
- **MINOR** increments when new features ship in a backward-compatible way.
- **PATCH** increments for backward-compatible bug fixes and security fixes.

Pre-release builds use the `-rcN` suffix (e.g. `v1.7.4-rc1`). Nightly builds are tagged from `main` and are not stable artifacts.

## Cadence

KubeArmor aims for a release roughly **every month**. The exact cut date depends on the readiness of features and tests on the release branch — releases are date-aspirational, not date-rigid.

- **MINOR releases** happen when a meaningful chunk of features has matured on `main` and a release branch has been cut and stabilized.
- **PATCH releases** happen on each maintained release branch on a rolling basis, typically monthly, to ship cumulative bug fixes.
- **Ad-hoc releases** are cut at any time when a critical bug or security issue cannot wait for the next scheduled release. The process is the same as a normal patch release but compressed and may skip the RC stage if the fix is small and well-isolated. The decision to skip an RC is made by the Release Manager in consultation with the Maintainers.

The roadmap and currently planned releases are visible on the [KubeArmor project board](https://github.com/orgs/kubearmor/projects/9).

## Branching strategy

- `main` is the active development branch. All feature work merges here first.
- Each MINOR release has a long-lived `release-vX.Y` branch. Patch releases are cut from this branch.
- Patch fixes land on `main` first, then are backported to the affected `release-vX.Y` branches via cherry-pick PRs.
- Hotfix-only commits (e.g., a backport that does not apply cleanly) may land directly on a release branch; the equivalent change must also be applied to `main` in the same release cycle.

The current stable release is recorded in [`STABLE-RELEASE`](./STABLE-RELEASE) at the repository root and is updated as part of the release checklist.

## Support window

<!--
TODO: Confirm the support window with the Maintainers.

Suggested default, modelled on Cilium: maintain the latest two MINOR releases. Older MINOR releases are unsupported and do not receive bug fixes or security patches except in exceptional cases agreed by the Maintainers.

Currently maintained branches (as of 2026-06): release-v1.7, release-v1.6.
-->

The project currently maintains the **latest two MINOR releases** with bug fixes and security patches. Older MINOR releases are unsupported and do not receive backports except by Maintainer agreement on a case-by-case basis.

When a new MINOR release ships, the oldest maintained MINOR release transitions to unsupported. End-of-life dates are announced in the release notes.

## Release Manager

Each release has a named **Release Manager** — a Maintainer who owns the release end-to-end.

Responsibilities:

- Open the release checklist issue using the [release checklist template](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue%20release%20checklist).
- Cut the release branch (for MINOR releases) and tag RC and final builds.
- Coordinate manual testing across the platforms listed in the checklist.
- Drive marketplace, Helm chart, and operator bundle updates.
- Write the release notes (or coordinate them with the contributing authors).
- Update `STABLE-RELEASE` once the release is published.

Release Manager rotation:

- The role rotates among Maintainers across releases. The next Release Manager is named at the start of each cycle.
- A first-time Release Manager is paired with a Maintainer who has shipped at least one previous release, to spread operational knowledge.

Current Release Manager: <!-- TODO: name the RM for the in-flight release (currently v1.7.4 — see issue #2704). The team should agree a rotation order and record it here. -->

## Release candidate (RC) stage

Every MINOR release goes through at least one RC stage before the final tag. PATCH releases follow the same RC flow unless the change is a small, well-isolated hotfix and the Release Manager (with Maintainer agreement) decides to skip.

The RC flow:

1. **Cut** — the Release Manager tags `vX.Y.Z-rc1` from the release branch. CI publishes container images, the operator bundle, and Helm charts under the `-rc1` tag.
2. **Test** — the manual checklist (platform tests, marketplaces, operator) is run against the RC. The RC remains testable for **at least one calendar week**. Issues found during RC testing are fixed on the release branch and a new RC is cut (`-rc2`, `-rc3`, ...).
3. **Promote** — once the checklist is clear and Maintainers agree the RC is ready, the Release Manager re-tags the same commit as `vX.Y.Z` and publishes the final artifacts.

## Release checklist

The release checklist is tracked as a GitHub issue per release. It covers manual platform tests, marketplace updates, the `STABLE-RELEASE` bump, helm chart release, and operator bundle review.

- **Current in-flight checklist:** [issue #2704 — v1.7.4 release checklist](https://github.com/kubearmor/KubeArmor/issues/2704)
- **All release checklists (open and closed):** [release-checklist issue search](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue%20release%20checklist)

Items typically covered (see issue #2704 for the canonical template):

- Manual tests on EKS (BottleRocket, Graviton, Amazon Linux 2), GKE COS (AppArmor and BPF-LSM), AKS (Ubuntu and Azure Linux), RHEL, minikube VM-based, and Docker Compose VM deployments.
- Performance benchmarking on BPF-LSM.
- Marketplace updates: AWS/EKS, Red Hat Catalog, MicroK8s plugin, DigitalOcean 1-Click App.
- Mark the release in `STABLE-RELEASE`.
- Refresh the helm getting-started guide.
- Confirm whether the [Operator bundle](./pkg/KubeArmorOperator/bundle) needs a manual update.
- Confirm helm charts have been released from the [charts](https://github.com/kubearmor/charts) repository.

The manual elements exist because some platforms cannot be exercised in CI for cost or licensing reasons.

## Release notes

Each release ships notes in the [release-notes directory](./getting-started/release-notes). Notes follow this shape:

- One-line summary at the top.
- **Highlights** — what users should know.
- **Features** — new capabilities.
- **Fixes** — notable bug fixes.
- **Breaking changes** — anything that requires user action (rare, only on MAJOR or pre-1.0 MINOR).
- **Known issues** — anything not yet fixed but worth being aware of.
- **Acknowledgements** — contributors to the release.

Notes are drafted in a pull request against `main` and merged just before the final tag is pushed.

## Coordinated releases

The following repositories under [github.com/kubearmor](https://github.com/kubearmor) are released in coordination with the main `KubeArmor` repository because their artifacts ship together:

- [`charts`](https://github.com/kubearmor/charts) — Helm charts, tagged in sync with each KubeArmor release.
- [`kubearmor-client`](https://github.com/kubearmor/kubearmor-client) — the `karmor` CLI, released independently but compatible with the latest two KubeArmor MINOR releases.
- The Operator bundle (lives in this repo under [`pkg/KubeArmorOperator`](./pkg/KubeArmorOperator)) — updated per the release checklist when the bundle changes.

See the [Related Repositories](./README.md#related-repositories) section of the README for the full inventory.

## Security releases

Security fixes are released either as part of a regular release (when the issue does not warrant urgency) or as an ad-hoc release (when it does). The disclosure timeline is described in [SECURITY.md](./SECURITY.md).

## Changing this document

This document is governed by `GOVERNANCE.md`. Changes follow the structural-vote process: a pull request open for at least 1 week and a two-thirds supermajority of Maintainers.
