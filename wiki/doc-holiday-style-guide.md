# doc.holiday Style Guide for KubeArmor

## Overview

This document defines how doc.holiday generates instructional documentation for the KubeArmor repository. It aligns doc.holiday output with existing wiki pages and the fallback documentation style guide used by automation.

## Scope

doc.holiday uses this style guide when generating or updating:

- How-to guides
- Concept overviews
- Task-focused walkthroughs
- FAQs and troubleshooting topics

Release notes and changelogs are out of scope.

## Target locations

doc.holiday writes instructional documentation to these locations:

- `wiki/` for feature and architecture overviews (for example, system monitor, log feeder, security policy)
- `getting-started/` for onboarding and quick-start style material

When documenting a feature that already has a wiki page, doc.holiday updates that page instead of creating a new one.

## Document structure

doc.holiday-generated instructional docs use this structure:

1. **Title** – H1 heading that states the topic clearly.
2. **Overview** – Short paragraph explaining what the topic is and why it matters.
3. **Prerequisites** – Bulleted list of required tools, permissions, or knowledge.
4. **Step-by-step instructions** – Numbered procedures for performing tasks.
5. **Examples** – Concrete examples based on KubeArmor usage and configuration.
6. **Tips and best practices** – Optional section for recommendations.
7. **Troubleshooting** – Optional section for common issues and resolutions.
8. **Related documentation** – Links to other wiki pages or guides.

## Formatting rules

- Use Markdown headings (`#`, `##`, `###`) to organize content.
- Use numbered lists for sequential steps.
- Use bullet lists for options or unordered items.
- Start each procedural step with an action verb.
- Use `inline code` for commands, configuration keys, and literal values.
- Use fenced code blocks for multi-line commands, logs, and configuration snippets.
- Use standard Markdown links with relative paths, for example `[Security policy guide](./security_policy.md)`.

## File naming

When doc.holiday creates new instructional files in this repository, it:

- Prefers topic-specific files over large monolithic documents.
- Uses descriptive kebab-case names, such as:
  - `system-monitor-alert-throttling.md`
  - `host-policy-visibility.md`
  - `container-default-posture.md`

If a topic clearly extends an existing page (for example, `wiki/system_monitor.md`), doc.holiday prefers to extend that page instead of creating a new file.

## Front matter

The existing KubeArmor instructional files in `wiki/` do not use front matter blocks. doc.holiday therefore does **not** add front matter to new or updated wiki pages.

## Tone and style

- Use clear, direct sentences.
- Write in the present tense.
- Describe behavior factually based on repository code and configuration.
- Avoid marketing language; focus on what users can do and how.

## Grounding rules for generated docs

doc.holiday must only describe behaviors and configuration options that are visible in:

- Repository source files (for example, `KubeArmor/monitor/systemMonitor.go`, `KubeArmor/config/config.go`, `KubeArmor/types/types.go`).
- Existing instructional documentation in this repository.

If a behavior or option is not observable in the repository, doc.holiday must not document it.
