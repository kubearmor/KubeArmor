# KubeArmor Podman Hook Deployer

This repository provides utilities for deploying the **KubeArmor Podman hook** required to use Podman with KubeArmor.  
The hook is installed under `/usr/share/kubearmor/hook`, allowing Podman containers to be managed securely with KubeArmor runtime enforcement.

---

## Components

- **deployHook**  
  A helper binary that deploys the KubeArmor hook binary into the correct location (`/usr/share/kubearmor/hook`).

- **hook**  
  The actual KubeArmor Podman hook binary that integrates Podman with KubeArmor.

Both binaries are built from Go source files under `DeployHook/` and `Hook/`.

---

## Build Instructions

To build both binaries and deploy the hook:

```bash
make deploy
