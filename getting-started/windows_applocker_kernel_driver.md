# AppLocker vs Kernel Driver — Windows Enforcement Guide

## Summary

| Capability | Kernel Driver (Minifilter) | AppLocker |
|---|---|---|
| File access enforcement | ✅ | ❌ |
| Directory enforcement | ✅ | ❌ |
| EXE process blocking | ✅ (suffix match by filename) | ✅ (path/publisher rule) |
| Script blocking (`.ps1`, `.bat`, `.cmd`, `.vbs`, etc.) | ✅ (as file rule) | ✅ (`Script` collection) |
| DLL blocking | ✅ (as file rule) | ✅ (`Dll` collection) |
| MSI blocking | ❌ | ✅ (`Msi` collection) |
| UWP/packaged app blocking | ✅(via binary path) | ✅ (`Appx` + `FilePublisherRule`) |
| Read-only enforcement | ✅ | ❌ |
| Recursive directory rules | ✅ | ❌ |
| Requires Application Identity service | ❌ | ✅ |
| Audit/allow event generation | ✅ (via driver events) | ✅ (via Windows Event Log) |

---

## Kernel Driver 

Minifilter driver allows:

- **File-level access control** is needed — read, write, or delete enforcement on arbitrary paths (analogous to eBPF file rules on Linux). AppLocker has no file-access enforcement.
- **Protecting sensitive files or directories** (e.g., credential stores, config files) regardless of which process attempts access.
- **AppLocker is not available** — the driver enforces EXE blocking on any Windows edition without requiring the Application Identity service or an Enterprise/Server license.
- **EXE blocking by filename**: The driver uses **suffix matching** — blocking any EXE with the specified filename regardless of install path.

---

## AppLocker — When It's Useful

Use AppLocker when:

- **Script blocking is required** (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsh`, `.wsf`). The driver cannot hook into script interpreters at the execution level; AppLocker's `Script` collection is the only effective mechanism.
- **UWP/MSIX packaged apps** must be blocked by publisher identity. `FilePublisherRule` in the `Appx` collection uses **cryptographic publisher matching** — more tamper-resistant than path-based rules.
- **DLL loading control** is needed — AppLocker's `Dll` collection can block DLL load events before they execute.
- **Windows Enterprise or Server** is available — AppLocker is fully licensed and the Application Identity service can be enabled.

> [!NOTE]
> AppLocker requires **Windows Enterprise, Education, or Windows Server** to enforce policies. The Application Identity service (`AppIDSvc`) must be running.
> See: [AppLocker OS requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker#operating-system-requirements)

---

## How KubeArmor Uses Both Together

KubeArmor applies a **dual-layer strategy** on every policy update:

1. **AppLocker first**: `applyAppLockerPolicy` is called before any driver IOCTL loop. AppLocker handles process, script, DLL, MSI, and packaged app rules where applicable.

2. **Driver as fallback for EXE**: If AppLocker fails (not licensed, Application Identity service not running, or policy application error), the driver's EXE process rules serve as a fallback using filename suffix matching.

3. **File/directory rules always go to the driver**: AppLocker has no file-access enforcement. All `file:` rules and `matchDirectories` under `process:` are exclusively handled by the Minifilter driver.

4. **Scripts and DLLs go to both**: Script interpreter paths and DLL paths are sent to both the AppLocker `Script`/`Dll` collections **and** the driver as file rules. This ensures enforcement even if one layer is unavailable.
```
Policy Update
     │
     ├──► applyAppLockerPolicy()
     │         ├── Exe collection    (FilePathRule)
     │         ├── Script collection (FilePathRule)
     │         ├── Dll collection    (FilePathRule)
     │         ├── Msi collection    (FilePathRule)
     │         └── Appx collection   (FilePublisherRule)
     │
     └──► IOCTL_CLEAR_RULES → driver
               ├── File/dir rules    (all file: spec rules)
               ├── EXE rules         (fallback if AppLocker failed)
               └── Script/DLL rules  (belt-and-suspenders)
```

---

## AppLocker Event Monitoring

KubeArmor polls these Windows Event Log channels every **5 seconds** using `wevtapi.dll`:

| Channel | Event ID | Trigger |
|---|---|---|
| `Microsoft-Windows-AppLocker/EXE and DLL` | 8004 | EXE execution blocked |
| `Microsoft-Windows-AppLocker/MSI and Script` | 8007 | Script execution blocked |
| `Microsoft-Windows-AppLocker/Packaged app-Execution` | 8022 | UWP/AppX launch blocked |

Each matching event is translated into a `MatchedHostPolicy` alert in the KubeArmor telemetry stream, including the blocked process path, the matched policy name, and severity metadata from the originating rule.

> [!NOTE]
> AppLocker event generation requires the Application Identity service to be running **and** the relevant AppLocker collections to be in **Enforced** mode. Audit-only mode emits different event IDs and is not currently mapped to KubeArmor alerts.
