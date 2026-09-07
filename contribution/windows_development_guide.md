# Windows Development Guide

This guide covers setting up a development environment to build and test the KubeArmor Windows minifilter driver (`pkg/KubeArmorWindowsDriver`), the KubeArmor userspace Go binary, and the MSI installer (`pkg/KubeArmorDriverInstaller`).

## Prerequisites

| Component | Minimum Version | Notes |
|---|---|---|
| Windows | 10 1809+ or Server 2016+ | Enterprise/Education recommended for AppLocker |
| Visual Studio | 2022 | With "Desktop development with C++" workload |
| Windows Driver Kit (WDK) | Matching SDK version | Must match SDK exactly |
| Windows SDK | 10.0.22000+ | Installed via VS installer |
| Go | 1.21+ | For userspace binary |
| WiX Toolset v3 | 3.11+ | For MSI packaging only |

> [!WARNING]
> The WDK version must exactly match the Windows SDK version installed. Mismatched versions cause build failures with cryptic MSBuild errors.

---

## Part 1: Driver Development Setup

### 1.1 Install Visual Studio, WDK, and SDK

Follow the official Microsoft provisioning guide:
[Provision a target computer for driver deployment](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/provision-a-target-computer#prepare-the-target-computer-for-provisioning)

Install in this order:
1. Visual Studio 2022 (with "Desktop development with C++" workload)
2. Windows SDK (via VS installer or standalone)
3. WDK (must match SDK version — download from [WDK download page](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))

### 1.2 Generate the Event Log Message File

The driver uses a custom ETW event manifest (`KarmorLogs.man`). Building requires the compiled message binary `MSG00001.bin` to be generated first.

**Step 1:** Clone the repository and navigate to the driver directory:

```powershell
git clone https://github.com/kubearmor/KubeArmor.git
cd KubeArmor\pkg\KubeArmorWindowsDriver
```

**Step 2:** Locate `mc.exe`. Run the following to check if it is on your `PATH`:

```powershell
mc
```

If not found, locate it manually. The typical path is:

```
C:\Program Files (x86)\Windows Kits\10\bin\<SDK_VERSION>\x64\mc.exe
```

You can search for it:

```powershell
Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin" -Recurse -Filter "mc.exe" |
    Where-Object { $_.FullName -match "x64" } |
    Select-Object FullName
```

**Step 3:** Either add the `mc.exe` directory to your `PATH`, or call it by full path. From inside `pkg/KubeArmorWindowsDriver`, run:

```powershell
mc.exe -km KarmorLogs.man
```

This generates `KarmorLogs.h`, `KarmorLogs.rc`, and `MSG00001.bin`. The `.bin` file is required for the driver build to succeed.

> [!NOTE]
> If `mc.exe` produces no output and exits cleanly, the files were generated successfully. Run `dir MSG00001.bin` to confirm.

### 1.3 Enable Test-Signing Mode

Kernel drivers must be signed. For local development, use test signing instead of production EV certificates.

> [!IMPORTANT]
> Secure Boot must be **disabled** before test signing can be enabled. On a VM, disable Secure Boot in the VM firmware settings. On bare metal, change it in BIOS/UEFI.

Open **Command Prompt as Administrator** and run:

```cmd
bcdedit /set testsigning on
```

**Reboot** the machine for the change to take effect. After reboot, a "Test Mode" watermark appears in the bottom-right corner of the desktop — this confirms test signing is active.

To disable test signing later:

```cmd
bcdedit /set testsigning off
```

### 1.4 Build the Driver in Visual Studio

1. Open `pkg/KubeArmorWindowsDriver/kubearmor.sln` in Visual Studio 2022.
2. Set the configuration to **Debug** and platform to **x64**.
3. Build the solution (**Build → Build Solution** or `Ctrl+Shift+B`).

Build output is written to:

```
pkg/KubeArmorWindowsDriver/x64/Debug/kubearmor/
```

The directory will contain:
- `kubearmor.sys` — the minifilter driver binary
- `kubearmor.inf` — the driver installation manifest
- `kubearmor.cat` — the test-signed catalog file

### 1.5 Install the Driver Manually

**Option A — Right-click install (simplest):**

In Explorer, navigate to `pkg/KubeArmorWindowsDriver/x64/Debug/kubearmor/`, right-click `kubearmor.inf`, and select **Install**.

**Option B — Command line:**

Open **Command Prompt as Administrator**:

```cmd
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 <full_path_to_kubearmor.inf>
```

### 1.6 Manage the Driver Service

After installation, use `sc` or `fltmc` from an **Administrator Command Prompt**:

```cmd
# Check driver installation and state
sc query kubearmor

# Load the minifilter (equivalent to fltmc load)
sc start kubearmor

# Unload the minifilter
sc stop kubearmor

# Remove the driver service entry
sc delete kubearmor
```

Alternatively, use `fltmc` directly:

```cmd
fltmc load kubearmor
fltmc unload kubearmor
fltmc filters          # list active filters
```

> [!NOTE]
> `sc start kubearmor` and `fltmc load kubearmor` are equivalent for minifilter drivers — both cause the Filter Manager to attach the driver. The KubeArmor userspace binary also attempts `fltmc load kubearmor` at startup, so manual loading is only needed when testing the driver standalone.

---

## Part 2: KubeArmor Userspace Binary

The userspace binary (`KubeArmor.exe`) is the Go service that loads policies, communicates with the driver over IOCTL, and manages AppLocker rules.

### 2.1 Install Go

Open **PowerShell as Administrator**:

```powershell
winget install GoLang.Go
```

Restart the terminal after installation so `go` is on your `PATH`.

### 2.2 Build the Binary

From the repository root:

```powershell
cd KubeArmor
$env:GOOS = "windows"
go build .
```

This produces `KubeArmor.exe` in the `KubeArmor/` directory.

> [!NOTE]
> The `GOOS=windows` override is only required when cross-compiling from a non-Windows host. On Windows, the default target is already `windows`.

### 2.3 Run KubeArmor

The driver must be loaded before starting the userspace binary. In an **Administrator PowerShell**:

```powershell
# Ensure the driver is loaded
fltmc load kubearmor

# Start KubeArmor in foreground mode (for debugging)
.\KubeArmor.exe -k8s=false -enableKubeArmorHostPolicy=true
```

To run as a registered Windows service instead:

```powershell
.\KubeArmor.exe install   # register the service
.\KubeArmor.exe start     # start it
.\KubeArmor.exe status    # verify
.\KubeArmor.exe stop      # stop
.\KubeArmor.exe uninstall # remove
```

See [windows_support.md](../getting-started/windows_support.md) for the full service lifecycle reference.

### 2.4 Verify the Driver IOCTL Channel

When KubeArmor starts successfully it logs:

```
Karmor driver device opened successfully for enforcement
AppLocker event-log poller started
```

If the driver device cannot be opened:

```
Failed to open Karmor driver device: ... (file enforcement disabled)
```

This means the driver is not loaded — run `fltmc load kubearmor` and restart.

---

## Part 3: MSI Installer Packaging

The `pkg/KubeArmorDriverInstaller` project bundles `kubearmor.sys`, `kubearmor.inf`, `kubearmor.cat`, and `KubeArmor.exe` into a single MSI that installs and registers everything automatically.

### 3.1 Install WiX Toolset v3

1. Download the latest **WiX v3** release from [GitHub](https://github.com/wixtoolset/wix3/releases).
2. Run the installer exe.
3. Install the [WiX Toolset Visual Studio 2022 Extension](https://marketplace.visualstudio.com/items?itemName=WixToolset.WixToolsetVisualStudio2022Extension) from the VS Marketplace.

> [!WARNING]
> WiX v4/v5 use a completely different project format and are **not** compatible with this `.wixproj`. Use WiX v3 only.

### 3.2 Build the MSI

The MSI project (`KubeArmorDriverInstaller.wixproj`) references the driver build outputs from `pkg/KubeArmorWindowsDriver/x64/Debug/kubearmor/` and the Go binary from `KubeArmor/KubeArmor.exe`.

**Build order:**

1. Build the driver (Part 1.4 above) — produces `kubearmor.sys`, `kubearmor.inf`, `kubearmor.cat`.
2. Build the Go binary (Part 2.2 above) — produces `KubeArmor.exe`.
3. Open `pkg/KubeArmorDriverInstaller/KubeArmorDriverInstaller.sln` in Visual Studio 2022.
4. Build the solution. The MSI is written to:

```
pkg/KubeArmorDriverInstaller/bin/Debug/KubeArmorDriverInstaller.msi
```

### 3.3 What the MSI Installs

The installer performs the following actions automatically:

| Action | Detail |
|---|---|
| Copies files | `kubearmor.sys`, `kubearmor.inf`, `kubearmor.cat`, `KubeArmor.exe` → `Program Files\KubeArmorDriverInstaller\` |
| Installs driver | `rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 kubearmor.inf` |
| Loads driver | `fltmc.exe load kubearmor` |
| Installs Windows service | Registers `KubeArmorSvc` with args `-k8s=false -enableKubeArmorHostPolicy=true` |
| Starts service | Starts `KubeArmorSvc` automatically |

On uninstall, the MSI reverses these steps: stops the service, unloads the driver (`fltmc unload kubearmor`), and runs `InstallHinfSection DefaultUninstall`.
