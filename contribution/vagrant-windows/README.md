# KubeArmor Windows Vagrant VM

A **Windows Server 2022** VirtualBox VM for developing and running
KubeArmor Windows policy tests locally, equivalent to the Linux
development VM in `contribution/vagrant/`.

---

## Prerequisites (Linux host)

| Tool | Min version | Install |
|---|---|---|
| VirtualBox | 6.1+ | `sudo apt install virtualbox` |
| Vagrant | 2.3+ | [hashicorp.com/vagrant](https://www.vagrantup.com/downloads) |
| vagrant-reload plugin | any | `vagrant plugin install vagrant-reload` |
| ~40 GB free disk | — | For box download + VM disk |
| 8 GB free RAM | — | VM uses 8 GB by default |

> **Note:** The `gusztavvargadr/windows-server-2022-standard` box is
> ~8 GB. First `vagrant up` will download it automatically.

---

## Quick Start

```bash
# From the repo root
cd contribution/vagrant-windows

# Boot and fully provision the VM (first run: ~30 min)
vagrant up

# Open an RDP session (password: vagrant)
# Any RDP client works; Remmina on Linux:
remmina -c rdp://vagrant:vagrant@localhost:33389

# SSH / WinRM shell (limited but useful for quick checks)
vagrant ssh
```

### Run the Ginkgo tests

**Option A — from inside the VM** (via RDP or `vagrant ssh`):

```powershell
cd C:\KubeArmor\tests\nonk8s_env
ginkgo -r --vv --flake-attempts=3 --timeout=20m .\windows_policy\
```

**Option B — from the Linux host** (requires the ginkgo binary and the
test module to be on the host too, with `KUBEARMOR_SERVICE` pointing at
the forwarded port):

```bash
export KUBEARMOR_SERVICE=localhost:32767
cd tests/nonk8s_env
GOOS=windows ginkgo -r --vv ./windows_policy/
```

---

## VM Configuration

| Setting | Default | Override |
|---|---|---|
| CPUs | 4 | `VM_CPUS=8 vagrant up` |
| RAM | 8192 MB | `VM_MEM=16384 vagrant up` |
| GUI | off | edit `vb.gui = true` in Vagrantfile |
| RDP port (host) | 33389 | auto-corrected if in use |
| gRPC port (host) | 32767 | auto-corrected if in use |

---

## What Gets Provisioned

| Step | Script | What it does |
|---|---|---|
| 1 | `01-system-prep.ps1` | Set ExecutionPolicy, enable TLS 1.2, install Chocolatey |
| 2 | `02-enable-test-signing.ps1` | `bcdedit /set testsigning on` so test-signed drivers load |
| — | *(reboot)* | bcdedit changes require a reboot |
| 3 | `03-install-go.ps1` | Install Go via Chocolatey (pinned version) |
| 4 | `04-install-git.ps1` | Install Git for Windows |
| 5 | `05-install-ginkgo.ps1` | `go install ginkgo` (pinned commit) |
| 6 | `06-enable-applocker.ps1` | Start AppIDSvc, enable event channels, apply allow-all baseline policy |
| 7 | `07-build-kubearmor.ps1` | `go build` inside `C:\KubeArmor\KubeArmor` |
| 8 | `08-install-kubearmor-service.ps1` | `KubeArmor.exe install && start`, wait for gRPC :32767 |

Steps 7 and 8 run on every `vagrant provision` so re-building after a
source change is just:

```bash
vagrant provision --provision-with build-kubearmor,install-kubearmor-svc
```

---

## Installing the Minifilter Driver (Optional)

The minifilter driver enables **file-access enforcement** (block rules
on files/directories). Without it, only **AppLocker process enforcement**
is active.

To install the driver inside the VM:

1. Build the driver on a Windows machine with Visual Studio + WDK:
   see `contribution/windows_development_guide.md`, Part 1.

2. Copy `kubearmor.sys`, `kubearmor.inf`, `kubearmor.cat` into the
   shared folder (e.g. `KubeArmor/pkg/KubeArmorWindowsDriver/x64/Debug/kubearmor/`).

3. Inside the VM (Administrator PowerShell):

```powershell
$infPath = "C:\KubeArmor\pkg\KubeArmorWindowsDriver\x64\Debug\kubearmor\kubearmor.inf"
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $infPath
fltmc load kubearmor
fltmc filters   # verify 'kubearmor' appears in the list
```

4. Restart KubeArmor:

```powershell
C:\KubeArmor\KubeArmor\KubeArmor.exe restart
```

---

## Testing and Validating

You can manually trigger the Ginkgo tests against your VM to verify that everything works:

```powershell
cd C:\KubeArmor\tests\nonk8s_env
ginkgo -r --vv ./windows_policy/
```

## Day-to-Day Workflow

```bash
# Rebuild KubeArmor.exe and restart the service after a source change
vagrant provision --provision-with build-kubearmor,install-kubearmor-svc

# Full reprovision (e.g. after a Go version bump)
vagrant provision

# Suspend / resume
vagrant suspend
vagrant resume

# Full teardown
vagrant destroy -f
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `vagrant up` hangs at "Waiting for machine to boot" | Box download slow, or VM not booting | Increase `config.vm.boot_timeout`; enable `vb.gui = true` to see the console |
| gRPC connection refused on `:32767` | KubeArmor service not started | `vagrant provision --provision-with install-kubearmor-svc` |
| AppLocker not blocking anything | AppIDSvc stopped | Inside VM: `Start-Service AppIDSvc` |
| Test-signed driver won't load | Test-signing not active | Confirm `bcdedit /enum | Select-String testsigning` shows `Yes`; reboot if not |
| `go build` fails with module errors | Shared folder not mounted | Check `vagrant status` and that VirtualBox Guest Additions are installed |
| Clock skew errors during build | VM clock drifted | `w32tm /resync /force` inside the VM |
