# Open Source Contribution Cycle Workflow

This document outlines the standard operating procedure (SOP) for making open-source contributions to KubeArmor. **Do not use this document as a rigid script for a single issue. Instead, follow this cycle for every new contribution.**

## The Work Cycle

### 1. Finding a New Issue
- Scan the KubeArmor codebase for unaddressed developer `TODO` comments or small maintenance tasks.
- Ensure the issue is genuine, unraised, and suitable for a contribution (strictly non-security related).
- **Important:** Do not fix an issue that has already been addressed in a previous PR (like the `initDeploy` flag or the `RELEASES.md` support window). Find a fresh one!

### 2. Creating a Branch
- Before making changes, create a new branch from `main` with a descriptive name (e.g., `docs/formalize-release-support` or `feat/some-new-feature`).

### 3. Raising the Issue
- The user must raise the issue on the KubeArmor GitHub repository.
- Use the appropriate issue template (e.g., "Feature request/Enhancement").
- Provide a clear description proposing the fix.
- Note the assigned **Issue Number** (e.g., `#2830`) so it can be referenced in the PR.

### 4. Solving the Issue
- Write the code or documentation changes to fix the issue on the new branch.
- Commit the changes using conventional commits (e.g., `docs: formalize release support window policy`).
- Push the branch to the user's fork.

### 5. Documenting the Cycle
- Once the PR is ready or opened, document the specifics of that contribution at the bottom of this very file (`pr_context.md`) under a new heading to keep track of past work and avoid repeating it.

---

## Log of Past Contributions

### Contribution 1: `initDeploy` Default Value
- **Issue:** Developer `TODO` in `pkg/KubeArmorOperator/cmd/operator/main.go` to set `initDeploy` to `false`.
- **Issue Number:** #2826
- **Status:** Completed in a previous PR.

### Contribution 2: Formalize Release Support Window
- **Issue:** Developer `TODO` hidden in an HTML comment in `RELEASES.md` regarding the release support window.
- **Fix:** Removed the `TODO` block to formalize the policy (maintaining the latest two MINOR releases) which was already documented right below it.
- **Issue Number:** #2830
- **Branch:** `docs/formalize-release-support`
- **Status:** PR Opened.

### Contribution 3: Store CA Certificate in Kubernetes Secret
- **Issue:** Developer `TODO` in `pkg/KubeArmorOperator/internal/controller/resources.go` to keep CA certificate in k8s secret.
- **Fix:** Updated `RotateTlsCerts` to fetch existing CA and TLS certs from the secret `kubearmor-controller-webhook-server-cert`. It reuses them if they are still valid instead of unconditionally regenerating new PKI on every operator restart.
- **Issue Number:** TBD (recently created)
- **Branch:** `fix-operator-ca-secret`
- **Status:** PR Opened.

### Contribution 4: Migrate CLI Flags to KubeArmorConfig CRD
- **Issue:** Developer `TODO` in `pkg/KubeArmorOperator/internal/controller/resources.go` to avoid hardcoding KubeArmor daemon version checks for the `-annotateResources` flag.
- **Fix:** Migrated `annotateResource` and `annotateExisting` configurations from Operator command-line flags to the `KubeArmorConfig` CRD. Updates are pushed to KubeArmor via `ConfigMapData` and the Operator's RBAC creation logic has been updated, safely removing the deprecated CLI flags.
- **Issue Number:** #2834
- **Branch:** `fix-kubearmorconfig-annotate`
- **Status:** PR Opened.

### Contribution 5: Remove Obsolete Regex TODO
- **Issue:** Developer `TODO: regex based matching` in `KubeArmor/core/unorchestratedUpdates.go` where the regex logic (`regexp.CompilePOSIX`) was already implemented immediately following the comment.
- **Fix:** Removed the obsolete TODO comment to keep the code clean.
- **Issue Number:** TBD (recently created)
- **Branch:** `chore/remove-obsolete-regex-todo`
- **Status:** PR Opened.
