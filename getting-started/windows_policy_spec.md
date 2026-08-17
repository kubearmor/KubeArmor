# Windows Policy Fields — `KubeArmorHostPolicy`

## Overview

On Windows, `KubeArmorHostPolicy` uses the same base schema as on Linux, but adds a **Windows-only field** under `process:` for targeting MSIX/AppX packaged applications.

Standard `matchPaths` and `matchDirectories` under `file:` and `process:` remain supported (with the exceptions listed in the field availability table below).

---

## New Field: `process.matchPackages`

**Type**: `[]PackageMatchType` — Windows only

Used to block UWP/MSIX packaged applications via AppLocker's `Appx` collection using `FilePublisherRule`. This field has no effect on Linux.

### `PackageMatchType` Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | Yes (if `packageFamily` omitted) | Package product name as reported by `Get-AppxPackage`. Supports glob wildcards (e.g., `*Notepad`). |
| `publisher` | `string` | No | Signing certificate Subject DN (e.g., `CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`). Omit or use `*` to match any publisher. |
| `packageFamily` | `string` | No | Package family name (`<name>_<publisherHash>`, e.g., `Microsoft.WindowsNotepad_8wekyb3d8bbwe`). Narrows the match when combined with `name`/`publisher`. |
| `action` | `string` | No | Rule-level action override. Only `Block` is currently enforced. |
| `severity` | `int` | No | Alert severity (1–10). |
| `tags` | `[]string` | No | Alert tags. |
| `message` | `string` | No | Alert message string. |

---

## How AppLocker Appx Enforcement Works

When `matchPackages` is specified, KubeArmor:

1. Calls `Get-AppxPackage` on the host to enumerate all installed packages.
2. Matches the `name` field as a **glob pattern** against installed package display names.
3. Emits a `FilePublisherRule` in the AppLocker `Appx` collection using the resolved publisher DN and product name.
4. Applies the updated AppLocker XML policy via `Set-AppLockerPolicy`.

> [!WARNING]
> `FilePathRule` entries do **not** work in the AppLocker `Appx` collection — AppLocker silently misinterprets them. KubeArmor routes packaged `.exe` files listed under `matchPaths` through the `Exe` collection instead, using a `*\<basename>` wildcard path pattern.

---

## Examples

### Block a Specific UWP App

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: block-windows-notepad
spec:
  nodeSelector:
    matchLabels:
      kubernetes.io/os: windows
  process:
    matchPackages:
    - name: "Microsoft.WindowsNotepad"
      publisher: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
      action: Block
      severity: 5
      message: "Notepad blocked by policy"
  action: Block
```

### Block Scripts and DLLs (AppLocker Script/Dll + Driver Fallback)

```yaml
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: block-powershell-script
spec:
  nodeSelector:
    matchLabels:
      kubernetes.io/os: windows
  process:
    matchPaths:
    - path: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
      action: Block
  action: Block
```

> [!NOTE]
> For script interpreter paths (`.ps1`, `.bat`, `.cmd`, `.vbs`, etc.), KubeArmor applies the rule to **both** the AppLocker `Script` collection and the driver file rules. This approach ensures enforcement even if AppLocker is unavailable.

---

## Field Availability Table

| Field | Windows Support | Notes |
|---|---|---|
| `matchPaths` | ✅ | EXE → AppLocker `Exe` + driver; Scripts/DLLs → AppLocker `Script`/`Dll` + driver file rules |
| `matchDirectories` | ❌ | Not supported for process enforcement on Windows |
| `matchPatterns` | ❌ | Not supported on Windows |
| `matchPackages` | ✅ (Windows only) | AppLocker `Appx` `FilePublisherRule` |
| `ownerOnly` | ❌ | Ignored on Windows |
| `fromSource` | ❌ | Ignored on Windows |
