# KubeArmor macOS Operational Packaging

This directory contains configuration templates and operational scripts for running the KubeArmor daemon on macOS as a managed, well-mannered background service.

---

## Features & Operational Controls

### 1. Automatic Startup & Recovery (LaunchDaemon)
- **Service Name:** `io.kubearmor.daemon`
- **Location:** `/Library/LaunchDaemons/io.kubearmor.daemon.plist`
- Automatically starts on system boot (`RunAtLoad`).
- Monitored by macOS `launchd` and restarted on crash or abnormal exit (`KeepAlive: { SuccessfulExit: false }`).
- Graceful shutdown timeout (`ExitTimeOut: 30`).

### 2. Sane Resource Quotas (CPU & Memory)
To ensure KubeArmor behaves transparently on developer laptops and does not compete with interactive workloads (compilers, IDEs, browser tasks):
- **macOS QoS Scheduling (`ProcessType: Adaptive`):** Instructs the kernel Quality of Service (QoS) scheduler to yield CPU to foreground user tasks during periods of system contention.
- **Process Niceness (`Nice: 1`):** Lowers daemon scheduling priority relative to interactive user processes.
- **Memory Ceiling:**
  - Soft memory limit of 512 MB in `io.kubearmor.daemon.plist`.
  - In-daemon Go runtime GC memory ceiling (`debug.SetMemoryLimit`) and data segment limits (`RLIMIT_DATA`) configured via `-maxMemoryMB` (default 512 MB on macOS).

### 3. Log Rotation (In-Daemon & System-Level)
Prevents unbounded disk usage by local telemetry, alerts, and operational logs:
- **In-Daemon Rotation (`LogRotator`):**
  - Monitors log file size before writes.
  - Automatically rotates active log files when size exceeds `-logMaxSizeMB` (default: 10 MB).
  - Maintains up to `-logMaxBackups` archives (default: 5 backups) and prunes oldest entries.
- **Native macOS `newsyslog` Configuration (`/etc/newsyslog.d/io.kubearmor.conf`):**
  - Periodically rotates `/var/log/kubearmor/kubearmor.log`, `kubearmor.out.log`, and `kubearmor.err.log`.
  - Rotates at 10 MB threshold, compresses archives with `bzip2` (`J` flag), and preserves 5 rotated backups.

---

## Directory Contents

| File | Purpose |
|---|---|
| `io.kubearmor.daemon.plist` | System-wide LaunchDaemon specification for background enforcement |
| `io.kubearmor.agent.plist` | User-session LaunchAgent specification for GUI login sessions / systray |
| `newsyslog.d/io.kubearmor.conf` | macOS `newsyslog` rotation rules for `/var/log/kubearmor/*.log` |
| `install.sh` | Automated installer script (sets directories, permissions, registers with `launchctl`) |
| `uninstall.sh` | Automated uninstaller script (stops daemon, unloads plist, cleans configs) |

---

## Quick Start

### Installation
Compile KubeArmor and run the installer as root:

```bash
# Build KubeArmor binary
make -C ../.. build

# Install daemon, LaunchDaemon plist, and newsyslog configuration
sudo ./install.sh
```

### Checking Daemon Status
Verify the service is active and running under `launchd`:

```bash
sudo launchctl list | grep io.kubearmor.daemon

# Detailed service state and resource usage:
sudo launchctl print system/io.kubearmor.daemon
```

### Viewing Logs
Inspect real-time logs:

```bash
# Telemetry and alert feed
tail -f /var/log/kubearmor/kubearmor.log

# Standard stdout / stderr output
tail -f /var/log/kubearmor/kubearmor.out.log
tail -f /var/log/kubearmor/kubearmor.err.log
```

### Testing Log Rotation
To manually trigger and verify `newsyslog` log rotation without waiting for the scheduled interval:

```bash
sudo newsyslog -v -F /etc/newsyslog.d/io.kubearmor.conf
```

### Uninstallation
To cleanly stop and remove the daemon:

```bash
# Preserve log files
sudo ./uninstall.sh

# Or completely purge logs and binaries:
sudo ./uninstall.sh --purge
```

---

## Configuration Reference

The following operational flags can be configured in `/opt/kubearmor/kubearmor.yaml` or passed via `ProgramArguments` in `io.kubearmor.daemon.plist`:

| Flag | Default (macOS) | Description |
|---|---|---|
| `-maxMemoryMB` | `512` | Memory ceiling in megabytes for daemon (Go runtime & RLIMIT) |
| `-niceLevel` | `1` | CPU scheduling nice priority (0 to 20) |
| `-logMaxSizeMB` | `10` | Maximum size in MB before local log file rotates |
| `-logMaxBackups` | `5` | Maximum number of rotated log backup archives to retain |
| `-logPath` | `/var/log/kubearmor/kubearmor.log` | Path to destination log file |
