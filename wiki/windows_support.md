# KubeArmor Windows Support

## Overview

KubeArmor supports **bare-metal and VM Windows hosts** with **host policy enforcement only**. Container-level enforcement (`KubeArmorPolicy`) is **not available** on Windows — only `KubeArmorHostPolicy` applies.

KubeArmor runs as a Windows Service named `KubeArmorSvc` and a minifilter kernel driver running as `kubearmor`, registered to start automatically on boot. Enforcement is provided by two cooperating layers: a **Minifilter Kernel Driver** and **AppLocker integration**.

---

## Architecture

### Enforcement Layers

```
┌─────────────────────────────────────────────────┐
│              KubeArmor (KubeArmorSvc)           │
│                                                 │
│  Policy Processor                               │
│       │                                         │
│       ├──► AppLocker (Set-AppLockerPolicy)      │
│       │        └── Exe / Script / Dll / Msi /   │
│       │             Appx collections            │
│       │                                         │
│       └──► Minifilter Driver (\Device\Karmor)   │
│                └── IOCTL_ADD_RULE               │
│                    IOCTL_REMOVE_RULE            │
│                    IOCTL_CLEAR_RULES            │
└─────────────────────────────────────────────────┘
```

### 1. Minifilter Kernel Driver (`kubearmor.inf`)

A Windows file system minifilter driver loaded by `fltmc`. It enforces **file and process access rules** at the kernel level.

- **Communication**: IOCTL from the KubeArmor service process
- **Rule struct**: `USER_RULE_REQUEST` — sent per-rule over one of three IOCTL codes:

| IOCTL Code | Action |
|---|---|
| `IOCTL_ADD_RULE` | Add a single rule to the driver |
| `IOCTL_REMOVE_RULE` | Remove a single rule |
| `IOCTL_CLEAR_RULES` | Flush all rules (called before every policy reload) |

### 2. AppLocker Integration

KubeArmor generates and applies an **AppLocker XML policy** via the `Set-AppLockerPolicy` PowerShell cmdlet. The policy uses:

- `FilePathRule` — for `Exe`, `Dll`, `Script`, `Msi` collections
- `FilePublisherRule` — for `Appx` collection (UWP/MSIX packaged apps)

**Event monitoring**: An AppLocker event-log poller (runs every **5 seconds** via `wevtapi.dll`) translates block events into KubeArmor `MatchedHostPolicy` alerts:

| Event Log Channel | Event ID | Meaning |
|---|---|---|
| `Microsoft-Windows-AppLocker/EXE and DLL` | 8004 | EXE blocked |
| `Microsoft-Windows-AppLocker/MSI and Script` | 8007 | Script blocked |
| `Microsoft-Windows-AppLocker/Packaged app-Execution` | 8022 | UWP/AppX blocked |

---

## Enforcement Model

Only `KubeArmorHostPolicy` is supported on Windows.

| Rule Type | Primary Enforcer | Fallback |
|---|---|---|
| File / Directory access | Minifilter Driver | — |
| EXE process blocking | AppLocker (`Exe` collection) | Driver (suffix match) |
| Script blocking (`.ps1`, `.bat`, `.cmd`, `.vbs`, etc.) | AppLocker (`Script` collection) | Driver file rule |
| DLL blocking | AppLocker (`Dll` collection) | Driver file rule |
| MSI blocking | AppLocker (`Msi` collection) | — |
| UWP / packaged app blocking | AppLocker `Appx` (`FilePublisherRule`) | — |

**Policy reload strategy**: On every policy update, KubeArmor issues `IOCTL_CLEAR_RULES` to the driver, then re-applies all current rules. This is a **clear-and-reload** approach — incremental patching is not used.

---

## Service Lifecycle

```bash
kubearmor.exe install    # Register KubeArmorSvc as a Windows service
kubearmor.exe start      # Start the service
kubearmor.exe stop       # Stop the service
kubearmor.exe restart    # Restart the service
kubearmor.exe uninstall  # Deregister the service
kubearmor.exe status     # Print current service state
```

> [!NOTE]
> On `uninstall`, KubeArmor resets AppLocker to its default allow-all baseline and flushes all driver rules via `IOCTL_CLEAR_RULES`.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| OS | Windows 10/11 Enterprise or Windows Server 2016+ |
| PowerShell | Must be available in system PATH |
| Application Identity service | Must be **enabled and running** for AppLocker enforcement |
| Privileges | Administrator rights required for service installation and driver loading |

---

## Limitations

> [!WARNING]
> The following capabilities are **not available** on Windows.

- **No container enforcement**: eBPF, AppArmor, and SELinux are Linux-only. `KubeArmorPolicy` (pod/container) is not enforced.
- **No network policy**: Network-level enforcement is not implemented.
- **AppLocker licensing**: AppLocker requires **Windows Enterprise, Education, or Windows Server**. On Home/Pro editions the Application Identity service exists but policy enforcement is not supported.
  See: [AppLocker OS requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker#operating-system-requirements)
- **`ownerOnly` and `fromSource`**: These process/file options are **ignored** on Windows — the enforcement stack has no equivalent mechanism.
- **Audit-only mode for processes**: AppLocker does not support per-rule audit mode in enforced collections. A rule either blocks or allows.
