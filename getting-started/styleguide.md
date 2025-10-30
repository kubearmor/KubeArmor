# Documentation Style Guide

## Project Summary

Project: getting-started

This repository is a documentation site containing 27 top-level Markdown files plus nested directories for release-notes and use-cases. The docs cover technical topics such as security policy specifications (host, cluster, workload), examples, deployment guides, visibility and hardening, profiling and events, and several use-case walkthroughs. The intended audience is technical readers — cluster administrators, security engineers, and developers who configure or operate the product. Content ranges from conceptual overviews (use cases, differentiation, deployment models) to prescriptive, example-driven API or YAML specifications (security policy specs and examples) and operational guides (deployment, profiling logs, release notes).

Purpose and goals
- Provide operational and reference documentation for security features, policy specification, and examples
- Offer step-by-step deployment and configuration guidance
- Present API/specification style reference (YAML/JSON/CLI examples) and troubleshooting/FAQ

Content types observed
- Reference / specification pages (security policy specification files: host, cluster, workload)
- Examples and sample policies (files named *_examples.md)
- How-to and deployment guides (deployment_guide.md, deployment_models.md)
- Use cases and scenario walkthroughs (use-cases/*)
- Release notes (release-notes/*)
- FAQ and conceptual pages (FAQ.md, differentiation.md)
- Operational notes and hardening guidance (hardening_guide.md, profiling_kubearmor_logs.md)

Technical complexity
- Medium to high: documentation contains API-like specification, YAML examples, and requires knowledge of container orchestration and security policy concepts.

Writing patterns & conventions (observed)
- Files are Markdown (.md) and organized by topic (specifications, examples, guides)
- Many files represent focused single-concept pages (one topic per file)
- Table of Contents present in files (TOC used to orient readers)
- Examples (code blocks) and API/policy specifications appear inline within pages
- No front-matter metadata detected in repository files (empty front matter set)

Key recommendations from analysis
- Enforce a single H1 per file using the human-readable page title (Title Case)
- Use structured H2/H3 headings for consistent navigation and automated table-of-contents
- Add a minimal front-matter template to support unknown publishing systems and CI validation (title, description, slug, sidebar_position, hide_table_of_contents optional)
- Use consistent internal linking (relative paths from documentation root) and prefer linking to directory README files where appropriate


## Context

**Project:** getting-started
**Description:** Documentation site with 27 documentation files
**Publishing System:** undefined

## Primary Documentation Goals

## Writing Rules

### Core Principles
- **Be concise** - Use the minimum words necessary
- **Be practical** - Focus on actionable information
- **Be example-driven** - Show working code for every concept
- **Be consistent** - Match existing documentation patterns

### Tone Guidelines

#### Default Tone (Technical Users)
- Direct and practical language
- Assume familiarity with TypeScript, package managers, CLI
- Use technical jargon and shorthand
- Focus on code examples over explanations
- Avoid marketing language or benefit statements

#### Non-Technical User Adjustments
When explicitly writing for non-technical users:
- Explain what each command does and why
- Spell out abbreviations and technical terms
- Provide simpler code examples with explanations
- Include more step-by-step guidance
- Link to additional learning resources

### Publishing System Requirements
Observed metadata: none (no front matter fields were present in repository files).

Because the publishing system is unknown, adopt a minimal, compatible front-matter schema that works with common static site generators (e.g., Docusaurus, Hugo, MkDocs) and enables future automation. The repository does not currently require front matter, but adding it consistently helps with navigation, search, and automated checks.

Required (recommended) metadata fields
- title: Human-friendly page title (string)
- description: One-sentence summary for search and previews (string)
- sidebar_position: Integer for ordering pages in navigation (optional but recommended)
- slug: URL path for the page (optional — system dependent)
- draft: true/false (optional — indicates not yet published)

Recommended optional metadata fields
- tags: list of short topic tags (security, deployment, policy)
- authors: names or IDs for traceability
- last_reviewed: YYYY-MM-DD
- hide_table_of_contents: true/false (if the page uses a custom TOC)

Exact front-matter template to add to the top of every .md (adapt to your publishing engine):

---
# Minimal front matter template — adapt or extend to match your site generator
title: "<Page Title>"
description: "<Short one-line summary of this page>"
slug: "/<optional-path>/<page-slug>"
sidebar_position: <integer>
draft: false
tags: ["security","policy"]
authors: ["<author-name>"]
last_reviewed: "YYYY-MM-DD"
hide_table_of_contents: false
---

Usage examples (code blocks inside docs)
- YAML policy example (for specification pages):

```yaml
apiVersion: security.example.com/v1
kind: WorkloadSecurityPolicy
metadata:
  name: example-policy
spec:
  match:
    selectors:
      - name: app
  rules:
    - name: deny-shell
      action: Block
      capabilities:
        - CAP_SYS_PTRACE
```

- CLI/example usage (shell code block):

```bash
# Install the agent
kubectl apply -f kubearmor-agent.yaml
# Apply an example security policy
kubectl apply -f host_security_policy_examples/example-deny.yaml
```

Publishing checklist (before merging docs):
- Ensure one H1 per document and it matches front-matter.title
- Add recommended front matter above or confirm system does not require it
- Validate all internal links (link-checker CI recommended)
- Confirm examples are syntax-highlighted and include expected output where helpful
- Add tags/authors/last_reviewed to enable discoverability and maintainability


### Content Structure Rules
General organization guidelines by page type

Technical Documentation / Reference pages (policy specs, API-like docs)
- Top: Purpose/Overview (one-paragraph summary)
- Next: Quick example (YAML/CLI snippet) to show a minimal working artifact
- Then: Specification details with clearly labeled sections (Fields, Types, Constraints)
- Provide validation examples, expected behavior, and common pitfalls
- End with Related resources and example files

How-to / Process / Deployment guides
- Top: Quick summary and intended audience
- Prerequisites: software, permissions, versions
- Steps: numbered lists, each step short and verifiable
- Validation: how to check success (commands, expected output)
- Troubleshooting: common errors and fixes
- Examples: complete working config and minimal variants

Example pages (snippets and sample policies)
- Keep examples runnable and minimal; include commentary for each block
- Use fenced code blocks with language labels (yaml, bash, json)
- Show expected results or output where applicable

Use-case and Concept pages
- Start with problem statement and scenario
- Walkthrough: what actions to take and why
- Map to product features and example policies
- Provide links to hands-on examples (use-cases/res/*)

Release Notes
- Brief summary at top for the release
- Bullet list of key changes (Features, Enhancements, Bug fixes)
- Link to relevant docs and upgrade guidance

FAQ / Troubleshooting pages
- Short question-and-answer pairs
- Link to deeper guides for step-by-step resolution

Formatting conventions
- Use sentence case for paragraph text but Title Case for headings
- Keep paragraphs short (1-3 sentences) and prefer bulleted lists for steps
- Use fenced code blocks for all examples and label the language
- Inline code uses backticks for commands, resource names, and field names
- Use consistent terminology (ex: "policy", "security policy", "host policy") — add a glossary if needed


#### Heading Rules
```markdown
H1 (Single per file)
- Use exactly one H1 per document as the primary title. Use Title Case and keep it short and human-friendly.
- Examples (derived from filenames):
  # Workload Visibility
  # Use Cases
  # Security Policy Specification
  # Deployment Guide
  # FAQ
- No trailing punctuation or special characters.

H2 (Major sections)
- Use for top-level sections such as Overview, Prerequisites, Specification, Examples, Usage, Troubleshooting, References, See also.
- Examples:
  ## Overview
  ## Prerequisites
  ## Configuration
  ## Examples
  ## Troubleshooting
  ## Related Resources
- Capitalization: Title Case for section names.

H3 (Subsections)
- Use for step breakdowns, parameter descriptions, API or field explanations, and example subheadings.
- Examples:
  ### CLI Installation
  ### YAML Example
  ### Fields
  ### Behavior

H4-H6 (Rare usage)
- Use only for deep technical breakdowns inside large sections (e.g., enumerating all fields of a complex spec).
- Prefer H3 for readability; H4+ only when necessary.

Additional rules
- Maintain H1 → H2 → H3 progression; do not skip heading levels (avoid going H2 → H4).
- Use consistent heading wording: every page should have Overview, Examples (if applicable), and References/See also as top-level H2s when relevant.
```

### Formatting Requirements

#### Lists

- Use bullets for unordered lists
- No periods at end of list items
- Use Oxford comma in series

### Code Example Requirements

1. Always include syntax highlighting with language tags
2. Always include a language tag when adding a code block
3. Show both input and expected output
4. Include comments for complex logic
5. Place runnable example near page top
6. Use codetabs for platform variants

### Linking Rules
**Internal Links**
- Use relative paths from documentation root for internal linking, without HTML extensions if your publishing system resolves them. Example syntaxes you can use (choose the one compatible with your generator):
  - Relative to root (explicit): [Use Cases](/use-cases/README.md)  <-- explicit relative example
  - Relative file path: [ModelArmor](use-cases/modelarmor.md)
  - Reference README as index for a section: [Use Cases](use-cases/README.md)
- Preferred pattern: link to directory README for a topic-level landing page; link to specific .md files for deep links to examples.
- When linking across directories, prefer path clarity: [Trusted Cert Bundle](use-cases/res/trusted-cert-bundle.md)

Exact internal link examples (pick the style your site accepts):
- [Use Cases](use-cases/README.md)
- [Trusted cert bundle](use-cases/res/trusted-cert-bundle.md)
- [v1.6 release notes](release-notes/v1.6.md)

**External Links**
- Use full URLs and open in the same tab (do not use shortened URLs).
- Example: [Kubernetes](https://kubernetes.io)
- For references to projects, standards, or external docs, always include the site name and full URL.

**Cross-Reference and Navigation Standards**
- Always prefer internal docs over external pages when a matching topic exists in the repo
- Use link text that clearly indicates the destination (avoid ambiguous "here" or "this page")
- When linking to code/config files, indicate the expected file path in parentheses if helpful
- Add link maintenance guidance: include a link-checker in CI to validate internal links on every merge; update links when files are moved and add redirects if the publishing system supports them

**When to use internal vs external**
- Use internal links for any content maintained in this repo (specs, examples, how-tos, release notes, use-cases)
- Use external links for upstream tools, Kubernetes resources, third-party docs, and standards

**Anchors and In-page Links**
- Use natural anchors matching the heading text where supported (e.g., [See Restrictions](#restrictions))
- If the publishing tool auto-generates anchors, reference the heading exact text (case-insensitive), but test anchors in the publishing environment to ensure compatibility

**Link formatting examples**
- Standard Markdown relative link: [Deployment Guide](deployment_guide.md)
- Relative nested link: [tmp-noexec use-case](use-cases/res/tmp-noexec.md)
- External link: [Kubernetes API Reference](https://kubernetes.io/docs/reference/)

**Link validation**
- Run a link-checker during CI builds; fail the build for broken internal links and surface broken external links as warnings
- When removing or renaming files, update all references and consider leaving a small redirect landing page if the site generator supports it


### Documentation Content Examples
- Below are examples of existing documentation that you should use for reference, including formatting, structure, layout, style, and language.
- The start and end of the following examples is marked by 10 dashes in a row, like this ----------. The 10 dashes in a row are not part of the formatting or content of the examples.

No examples available in the analyzed documentation.

## Existing Documentation Directory Structure
Top-level layout and purpose (inferred from repository):

./
- workload_visibility.md — Visibility concepts for workloads (overview and examples)
- use-cases.md — Index or landing page for use-cases (entry to use-cases/ folder)
- usb_device_class.md — Topic-specific reference (USB device class details)
- support_matrix.md — Support/platform compatibility matrix
- security_policy_specification.md — Primary specification for security policy (likely cluster/workload/host references)
- security_policy_examples.md — Example policies for quickstart and common use cases
- release_notes.md — Landing page for release-notes folder
- profiling_kubearmor_logs.md — How-to for profiling and logs
- network_segmentation.md — Conceptual/implementation details for segmentation
- least_permissive_access.md — Guidance document for permission models
- kubearmor_vm.md — VM-related deployment or behavior notes
- kubearmor_visibility.md — Visibility features & configuration
- kubearmor_apparmor_implementation_overview.md — Implementation overview with technical details
- kubearmor-security-enhancements.md — Security feature set and rationale
- kubearmor-events.md — Event model and handling
- host_security_policy_specification.md — Host-level policy spec
- host_security_policy_examples.md — Host-level policy examples
- hardening_guide.md — System hardening best practices
- FAQ.md — Frequently asked questions
- differentiation.md — Product differentiation and overview
- deployment_models.md — High-level deployment options
- deployment_guide.md — Step-by-step deployment instructions
- default_posture.md — Default security posture description
- consideration_in_policy_action.md — Policy action considerations and side effects
- cluster_security_policy_specification.md — Cluster-level policy spec
- cluster_security_policy_examples.md — Cluster-level examples
- alert_throttling.md — Guidance on alert throttling and tuning

release-notes/
- v1.6.md, v1.5.md, v1.4.md, ... — Versioned release notes (chronological changelogs). Keep each version as a single file; link from root release_notes.md.

use-cases/
- README.md — Use-cases index/landing page
- modelarmor.md, modelarmor-pickle-code.md, modelarmor-deploy-pytorch.md, modelarmor-adverserial-attacks.md, hardening.md — Individual use-case pages and deep dives

use-cases/res/
- trusted-cert-bundle.md, tmp-noexec.md, svc-act-token-alert.md, ... — Re-usable sub-resources and small scenario documents referenced by use-case pages

Directory organization rules
- Put concept/overview pages at repository root for discoverability (e.g., deployment_models.md, differentiation.md)
- Place versioned artifacts in clearly named subfolders (release-notes/*) and keep each version in a single file
- For multi-page topics, use a folder and a README.md landing page (as used by use-cases)
- Keep examples and specs adjacent: specification pages (security_policy_specification.md) and example pages (security_policy_examples.md / host_security_policy_examples.md / cluster_security_policy_examples.md)
- Short, reusable scenario/content pieces belong in subfolders (use-cases/res) and should be referenced from higher-level pages



*Generated on: 2025-10-30T05:49:00.821Z*
