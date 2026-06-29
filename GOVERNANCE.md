# KubeArmor Governance

This document describes how the KubeArmor project is governed. It covers project scope, roles, decision-making, vendor neutrality, sub-teams, the release process, and how this document itself is changed.

It applies to the KubeArmor project and all repositories under [github.com/kubearmor](https://github.com/kubearmor), unless a specific repository's `GOVERNANCE.md` overrides it.

## Mission and scope

KubeArmor is a cloud-native runtime security enforcement system. The project's mission is to make least-permissive runtime security accessible to containers, pods, VMs, and bare-metal workloads by exposing Linux LSMs and eBPF behind a portable policy model.

KubeArmor is a Cloud Native Computing Foundation (CNCF) Sandbox project. It is developed in the open and welcomes contributions from individuals and organizations regardless of affiliation.

## Code of Conduct

KubeArmor adopts the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md) without modification. All participants in project spaces (GitHub, Slack, community calls, mailing lists, in-person events) are expected to follow it.

See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) for the project-side reporting path.

## Vendor neutrality

KubeArmor is a vendor-neutral project. The project's direction, governance, and decisions are not controlled by any single company.

To enforce this in practice:

- **Affiliation disclosure.** Every Maintainer's company affiliation is listed in [MAINTAINERS.md](./MAINTAINERS.md). Changes in affiliation must be reflected within 30 days.
- **Communication channels.** Project communication (issues, PRs, design docs, Slack, community calls, blog posts on kubearmor.io) must be conducted in public, project-owned channels — not vendor-owned ones.
- **Branding.** Project websites, talks, and assets must not present any single company as owning, leading, or initiating the project beyond acknowledging the donating organization (AccuKnox) for historical context.

## Roles

KubeArmor recognises four contributor roles plus an honorific tier. Roles are described from least to most responsibility.

### Community Member

Anyone participating in project spaces — asking questions, reporting bugs, attending community calls, helping in Slack. No formal requirements.

### Contributor

A Community Member who has had at least one substantive contribution accepted: code, documentation, policy templates, tests, designs, or community work (release management, talks, content). Listed in `git log` and the [GitHub contributor graph](https://github.com/kubearmor/KubeArmor/graphs/contributors).

### Reviewer

A Contributor who is trusted to review pull requests in a specific area of the codebase. Reviewers do not have merge authority but their `LGTM` is a precondition for merge in their area.

**Requirements (defaults — confirm with maintainers):**

- Active Contributor for at least 3 months.
- Has been the primary reviewer on at least 5 merged pull requests.
- Has authored at least 5 merged pull requests in the area they wish to review.
- Sponsored by an existing Maintainer.

**Process:** A Maintainer opens a pull request adding the candidate to `CODEOWNERS` for the relevant path(s). Approval is by lazy consensus among Maintainers (see Decision making).

### Maintainer

A Reviewer who shares responsibility for the project's health: code, releases, governance, conduct, and outreach. Maintainers have merge authority and are listed in [MAINTAINERS.md](./MAINTAINERS.md) with their GitHub handle and company affiliation.

**Maintainers are expected to:**

- Maintain the mission, values, and scope of the project.
- Review and merge contributions in their area.
- Triage issues and steward releases.
- Address Code of Conduct reports promptly when they reach the maintainer list.
- Participate in maintainer discussions and votes.
- Refine governance and other project documents as the community grows.
- Disclose company affiliation and update it when it changes.

**Requirements (defaults — confirm with maintainers):**

- Active Reviewer for at least 3 months.
- Has authored or reviewed at least 30 merged pull requests across the project.
- Sponsored by an existing Maintainer.

**Process:** Any current Maintainer can nominate a candidate by opening a pull request adding them to MAINTAINERS.md (and the appropriate `CODEOWNERS` entries). A nomination passes when it receives a simple majority of Maintainer votes within a 1-week voting window. The candidate cannot vote on their own nomination.

### Emeritus Maintainer

A former Maintainer who has stepped down voluntarily or has become inactive (see Inactivity below). Emeritus Maintainers retain credit and may be re-invited if they become active again. They do not vote, do not have merge rights, and are not on `CODEOWNERS`.

Emeritus Maintainers are listed in a dedicated section of MAINTAINERS.md.

## Inactivity and removal

A Maintainer is considered **inactive** if they have not contributed to the project (commits, PR reviews, design participation, release work, or community calls) in the past <!-- TODO: agreed inactivity window — suggested default 6 months, in line with Falco MAINTAINERS_GUIDELINES.md and Cilium CONTRIBUTOR-LADDER.md. Confirm with the team. --> months. The Maintainer pool reviews activity quarterly using the [CNCF DevStats dashboard](https://kubearmor.devstats.cncf.io/) as the primary signal.

If a Maintainer is inactive:

1. Another Maintainer reaches out privately (Slack or email) to ask if they intend to remain active.
2. If the response is "no" or there is no response within two weeks, a pull request is opened moving the person from the Maintainers section to the Emeritus section of MAINTAINERS.md.
3. Voluntary moves to Emeritus pass by lazy consensus.

A Maintainer may be removed involuntarily for sustained inactivity, repeated Code of Conduct violations, or behavior that materially damages the project. Involuntary removal requires a two-thirds supermajority of Maintainer votes in a 1-week voting window. The subject of the vote is not eligible to vote on their own removal.

A Maintainer may step down at any time by opening a pull request moving themselves to the Emeritus section.

## Decision making

The default decision-making mechanism is **lazy consensus** on a public pull request or issue. A change is accepted when no Maintainer raises a substantive objection within a reasonable review window (typically 72 hours for code, 1 week for governance).

When lazy consensus fails or the decision is significant, a **vote** is called by any Maintainer. There are three classes of vote:

| Class | Examples | Threshold | Voting window |
|---|---|---|---|
| Ordinary | Adding a Maintainer or Reviewer, merging a contested PR, scoping a release | Simple majority of voting Maintainers | 1 week (extendable to 3) |
| Sensitive | Code of Conduct enforcement, security disclosures, anything involving an individual's privacy | Simple majority, conducted in a private channel reachable by all Maintainers | 1 week |
| Structural | Changes to this `GOVERNANCE.md`, changes to vendor-neutrality rules, removal of a Maintainer | Two-thirds supermajority of voting Maintainers | 1 week (extendable to 3) |

A Maintainer cannot vote on a matter where they are the subject (e.g., their own promotion, removal, or CoC report).

## Sub-teams

The Maintainers may create sub-teams to handle a specific function (security response, release management, outreach, infrastructure). Each sub-team has a charter — a one-page document checked into the repository — covering:

- The sub-team's responsibility.
- How members are nominated, onboarded, and removed.
- How decisions inside the sub-team are made.
- How the sub-team reports back to the Maintainers.

A sub-team is created by ordinary vote and dissolved by the same mechanism.

### Security Response Committee (SRC)

The Security Response Committee receives vulnerability reports, coordinates fixes, and manages disclosure. It is the first sub-team formally chartered under this governance.

Membership: drawn from Maintainers and contributors with security expertise. Nomination is by an existing SRC member, seconded by a Maintainer, followed by a shadow period of at least one disclosure cycle before full voting membership.

Current members are listed in [SECURITY.md](./SECURITY.md). <!-- TODO: SRC roster needs to be populated. Currently the project security email routes through support@accuknox.com — moving to a project-owned alias is tracked as a separate change. -->

Reporting path and process: see [SECURITY.md](./SECURITY.md).

## Subprojects

KubeArmor consists of a primary repository ([github.com/kubearmor/KubeArmor](https://github.com/kubearmor/KubeArmor)) and several supporting repositories under the same organization. The full inventory is listed in the [Related Repositories](./README.md#related-repositories) section of the README.

Each subproject under `github.com/kubearmor` falls into one of two categories:

- **Core subprojects** — governed by this document and by the Maintainers list. Their `CODEOWNERS` is a subset of the project Maintainers. Examples: `kubearmor-client`, `charts`, `kubearmor.io`.
- **Community subprojects** — community-driven, with their own `MAINTAINERS.md` or `OWNERS` and a notice in their README declaring autonomy from core governance for technical decisions, while still bound by this document for Code of Conduct and vendor-neutrality rules. Example: `policy-templates`.

If a subproject's status is ambiguous, the Maintainers decide its classification by ordinary vote.

## Release process

Releases follow the documented process in [RELEASES.md](./RELEASES.md). At a high level: a monthly release cadence, with a release candidate (RC) for each stable release, ad-hoc releases when a critical bug or security issue requires one, and a rotating Release Manager.

Each release is tracked by a `release checklist` issue in the main repository. See [open and closed release checklists](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue%20release%20checklist) and [issue #2704](https://github.com/kubearmor/KubeArmor/issues/2704) as the current example.

## Roadmap and contribution acceptance

The project roadmap is tracked publicly on the [KubeArmor Projects board](https://github.com/orgs/kubearmor/projects/9).

- New features, bugs, and proposals enter as GitHub issues.
- Issues are triaged into the project board by any Maintainer.
- Significant features require a written proposal (a markdown file under `proposals/` or a GitHub Discussion) and acceptance by Maintainer ordinary vote before implementation begins.
- Routine bug fixes and small enhancements follow the standard pull request flow with lazy consensus.

## CNCF requests and integrations

Requests to the CNCF on behalf of the project — including TOC interactions, TAG presentations, project-level applications, marketing assets, and changes to the project's CNCF metadata — are made by a Maintainer after ordinary vote among the Maintainers.

## Changing this document

Changes to `GOVERNANCE.md` are made by pull request and require a structural (two-thirds supermajority) vote of the Maintainers. The pull request must remain open for at least 1 week to allow review by all Maintainers and the community.

## Licenses and the DCO

The following licenses and contributor agreements apply to KubeArmor:

- [Apache License 2.0](https://opensource.org/licenses/Apache-2.0) for code.
- [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode) for documentation.
- The [Developer Certificate of Origin](https://developercertificate.org/) is required on every commit (via the `Signed-off-by` trailer).
