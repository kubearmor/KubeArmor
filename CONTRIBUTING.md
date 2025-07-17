# Contributing to KubeArmor

Welcome to KubeArmor, and thank you for showcasing your interest in contributing to the KubeArmor [community](https://github.com/kubernetes/community). We are excited to have you join us in improving Linux runtime security through Kubernetes. The KubeArmor community abides by the CNCF [code of conduct](code-of-conduct.md). Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of fostering an open and welcoming community, we pledge to respect all people who contribute through reporting issues, posting feature requests, updating documentation, submitting pull requests or patches, and other activities._

Since, KubeArmor is part of the Kubernetes Community, we request you to also go through the following:

- [Contributor License Agreement](https://github.com/kubernetes/community/blob/master/CLA.md): Kubernetes projects require that you sign a Contributor License Agreement (CLA) before we can accept your pull requests.
- [Kubernetes Contributor Guide](https://www.kubernetes.dev/docs/guide/): Main contributor documentation.
- [Contributor Cheat Sheet](https://github.com/kubernetes/community/blob/master/contributors/guide/contributor-cheatsheet.md): Common resources for existing developers.

## Getting Started

If you are new to the project or open source contributions in general, we encourage you to start by familiarizing yourself with KubeArmor via our KubeArmor Overview [Wiki](https://docs.kubearmor.io/kubearmor/quick-links/kubearmor_overview).

We maintain a list of curated issues that are great entry points:
- [Good First Issues](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22): Ideal for Beginners or new comers.
- [Help Wanted Issues](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
- [Backlog Issues](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue+is%3Aopen+label%3Abacklog): Issues that are planned or pending implementation. These are great for contributors looking for meaningful and scoped technical work.

For help setting up your development environment, refer to our [Development Guide](contribution/development_guide.md). To understand how to fork the repository and raise a PR, see our [Contribution Guide](contribution/contribution_guide.md).

## Installation

To begin contributing with code, it's essential to set up KubeArmor locally. Please refer to our [Development Guide](contribution/development_guide.md) for a step-by-step process to configure your environment and install necessary dependencies.

## Scope of Contribution

Contributions to KubeArmor are not limited to code. We welcome all kinds of improvements that help grow the ecosystem. Below are the different ways to contribute:

### Code Contributions
- Implement features or enhancements.
- Fix bugs and vulnerabilities.
- Write and improve unit tests, integration tests, and end-to-end tests.
- Ensure that each new feature or bug fix is covered with appropriate test cases.
- Refactor or optimize existing code without altering functionality.

### Non-Code Contributions
- **Documentation**: Enhance existing documentation, fix typos, improve structure and readability, or add new content such as usage guides and tutorials.
- **Community Engagement**: Help moderate GitHub Discussions, participate in Slack conversations, answer user queries, and assist with onboarding new contributors.
- **Content Creation**: Write technical blogs, create visual content, or prepare conference presentations, videos, or policy templates that promote KubeArmor and educate the community.

Test coverage is crucial for the stability and maintainability of the project. When submitting new code, contributors are encouraged to:
- Add relevant unit tests in the corresponding test files.
- Include integration tests to validate how your feature interacts within the full system.
- Follow test naming conventions and use mocking/stubbing as needed.
- Run all tests locally before submitting a pull request.

### Policy Templates
- Contribute reusable and community-relevant [Policy Templates](https://github.com/kubearmor/policy-templates).
- Example: A system policy to restrict access to the NGINX process that is applicable across many environments.

### Writing Blogs
- Tutorials explaining the use of KubeArmor features (e.g., KVMService, Event Auditor, Visibility).
- Use-case focused articles explaining how KubeArmor secures workloads.
- Deep-dives into technical integrations and real-world deployment examples.

### Community Engagement
- Participate in discussions on [GitHub Issues](https://github.com/kubearmor/KubeArmor/issues).
- Join Slack conversations (see below).
- Attend and engage in KubeArmor community meetings.

### Feedback and Evangelism
- Share feedback, suggest features, or discuss architectural decisions.
- Speak about KubeArmor in community meetups and security forums.
- Share slides, documentation, or user experiences with the team.

## Mentorship and Growth Opportunities

KubeArmor is dedicated to supporting contributors at all levels. Here’s how you can grow within the community:

### Get Started
- Begin by solving [Good First Issues](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue+label%3A%22good+first+issue%22).
- Familiarize yourself with the project architecture, contribution workflow, and Git practices such as writing meaningful commit messages and signing your commits using `git commit -s`.
- Take on more challenging issues from the [Backlog](https://github.com/kubearmor/KubeArmor/issues?q=is%3Aissue+label%3Abacklog) or those marked as `help wanted`.
- Participate in technical discussions, review pull requests, and propose improvements to existing modules.
- Work on testing improvements, documentation, CI pipelines, or system design tasks.

### Join Mentorship Programs
You can contribute to KubeArmor through several open source mentorship programs:
- **[Google Summer of Code (GSoC)](https://summerofcode.withgoogle.com/)**: Contribute to well-defined projects under the mentorship of KubeArmor maintainers. GSoC typically runs in summer and is supported by CNCF.
- **[LFX Mentorship](https://lfx.linuxfoundation.org/tools/mentorship/)**: Participate in guided mentorships under CNCF and Linux Foundation, working on security, observability, and performance improvements in KubeArmor.

Details of active or upcoming mentorship projects will be listed on the [LFX Mentorship portal](https://lfx.linuxfoundation.org/tools/mentorship/).

### Become a Mentor
Experienced contributors who consistently contribute with quality code and help others can become mentors by:
- Supporting new contributors via Slack, GitHub, and community calls.
- Sharing best practices and reviewing pull requests.

### Progress Toward Maintainer
Contributors who show initiative, strong technical ability, consistent engagement, and leadership will be considered for maintainer roles. Maintainers are responsible for:
- Reviewing and approving PRs.
- Triage and manage issue backlog.
- Guiding contributors and driving technical initiatives.
- Shaping the direction and roadmap of the project.

## Getting Help

If you have any questions or need help while contributing:

- **Slack Community**: Join the KubeArmor [Slack](https://cloud-native.slack.com/archives/C07EF44HWQM) to engage in real-time discussions.
- **Community Meetings**: Attend our regular meetings listed in our [GitHub README](https://github.com/kubearmor/KubeArmor#community).
- **GitHub Discussions**: Use [GitHub Discussions](https://github.com/kubearmor/KubeArmor/discussions) for long-form questions and ideas.
- **Documentation**: Refer to KubeArmor [Docs](https://docs.kubearmor.io/) for in-depth information.
- **FAQs**: Common queries and tips can be found in our README [FAQ Section](https://github.com/kubearmor/KubeArmor#frequently-asked-questions).

We look forward to your valuable contributions. Thank you for being part of the KubeArmor community!

