# Security Policy
The Maintainers and contributors to KubeArmor take the security of our software seriously. 
The KubeArmor community has adopted the below security disclosures and response policy to promptly respond to critical issues.

Please do not report security vulnerabilities through public GitHub issues.

## Security bulletins
For information regarding the security of this project please join our [slack channel](https://join.slack.com/t/kubearmor/shared_invite/zt-2bhlgoxw1-WTLMm_ica8PIhhNBNr2GfA).

## Reporting a Vulnerability
### When you should?
- You think you discovered a potential security vulnerability in KubeArmor.
- You are unsure how a vulnerability affects KubeArmor.
- You think you discovered a vulnerability in the dependency of KubeArmor. For those projects, please leverage their reporting policy.

### When you should not?
- You need assistance in configuring KubeArmor for security - please discuss this is in the [slack channel](https://join.slack.com/t/kubearmor/shared_invite/zt-2bhlgoxw1-WTLMm_ica8PIhhNBNr2GfA).
- You need help applying security-related updates.
- Your issue is not security-related.

### Please use the below process to report a vulnerability to the project:
1. Email the **KubeArmor security group at support@accuknox.com**

    * Please include the requested information listed below (as much as you can provide) to help us better understand the nature and scope of the possible issue:
        * Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
        * Full paths of the source file(s) related to the manifestation of the issue
        * Location of the affected source code (tag/branch/commit or direct URL) 
        * Any special configuration required to reproduce the issue
        * Step-by-step instructions to reproduce the issue
        * Proof-of-concept or exploit code (if possible)
        * Impact of the issue, including how an attacker might exploit the issue

    * These information will help us triage your report more quickly.

2. The project security team will send an initial response to the disclosure in 3-5 days. Once the vulnerability and fix are confirmed, the team will plan to release the fix in 7 to 28 days based on the severity and complexity.

3. You may be contacted by a project maintainer to further discuss the reported item. Please bear with us as we seek to understand the breadth and scope of the reported problem, recreate it, and confirm if there is a vulnerability present.

## Supported Versions
KubeArmor versions follow [Semantic Versioning](https://semver.org/) terminology and are expressed as x.y.z:
- where x is the major version
- y is the minor version
- and z is the patch version

Security fixes may be backported to some recent minor releases, depending on severity and feasibility. Patch releases are cut from those branches periodically, plus additional urgent releases, when required.
