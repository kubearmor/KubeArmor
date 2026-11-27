#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLIST_NAME="io.kubearmor.daemon.plist"
DAEMON_PLIST_SRC="${SCRIPT_DIR}/${PLIST_NAME}"
DAEMON_PLIST_DST="/Library/LaunchDaemons/${PLIST_NAME}"
NEWSYSLOG_SRC="${SCRIPT_DIR}/newsyslog.d/io.kubearmor.conf"
NEWSYSLOG_DST="/etc/newsyslog.d/io.kubearmor.conf"
BIN_DIR="/opt/kubearmor"
LOG_DIR="/var/log/kubearmor"

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This installation script must be run as root (e.g. using sudo)." >&2
    exit 1
fi

echo "=== Installing KubeArmor on macOS ==="

# 1. Create target directories
echo "Creating application and log directories..."
mkdir -p "${BIN_DIR}"
mkdir -p "${LOG_DIR}"
chmod 755 "${BIN_DIR}"
chmod 755 "${LOG_DIR}"

# 2. Install binary if found in build or distribution location
if [ -f "${SCRIPT_DIR}/../../kubearmor" ]; then
    echo "Installing compiled KubeArmor binary to ${BIN_DIR}/kubearmor..."
    cp "${SCRIPT_DIR}/../../kubearmor" "${BIN_DIR}/kubearmor"
    chmod 755 "${BIN_DIR}/kubearmor"
elif [ -f "./kubearmor" ]; then
    echo "Installing local KubeArmor binary to ${BIN_DIR}/kubearmor..."
    cp "./kubearmor" "${BIN_DIR}/kubearmor"
    chmod 755 "${BIN_DIR}/kubearmor"
elif [ ! -f "${BIN_DIR}/kubearmor" ]; then
    echo "Note: KubeArmor binary not yet present at ${BIN_DIR}/kubearmor. Place the compiled binary there before launching."
fi

# 3. Install LaunchDaemon plist
echo "Installing LaunchDaemon plist to ${DAEMON_PLIST_DST}..."
cp "${DAEMON_PLIST_SRC}" "${DAEMON_PLIST_DST}"
chown root:wheel "${DAEMON_PLIST_DST}"
chmod 644 "${DAEMON_PLIST_DST}"

# 4. Install newsyslog rotation config
if [ -f "${NEWSYSLOG_SRC}" ]; then
    echo "Configuring macOS newsyslog rotation at ${NEWSYSLOG_DST}..."
    mkdir -p "/etc/newsyslog.d"
    cp "${NEWSYSLOG_SRC}" "${NEWSYSLOG_DST}"
    chown root:wheel "${NEWSYSLOG_DST}"
    chmod 644 "${NEWSYSLOG_DST}"
fi

# 5. Bootstrap and load the daemon via launchctl
echo "Bootstrapping LaunchDaemon with launchctl..."
# Modern launchctl (macOS 10.11+) uses bootstrap
if launchctl list io.kubearmor.daemon >/dev/null 2>&1; then
    echo "Reloading existing service..."
    launchctl bootout system/io.kubearmor.daemon 2>/dev/null || launchctl unload "${DAEMON_PLIST_DST}" 2>/dev/null || true
fi

if launchctl bootstrap system "${DAEMON_PLIST_DST}" 2>/dev/null; then
    echo "Successfully bootstrapped io.kubearmor.daemon with launchctl."
else
    echo "Fallback: loading with legacy launchctl load..."
    launchctl load -w "${DAEMON_PLIST_DST}" || true
fi

echo "=== KubeArmor macOS Installation Complete ==="
echo "Check daemon status with: sudo launchctl list | grep io.kubearmor.daemon"
echo "Check active logs with:   tail -f ${LOG_DIR}/kubearmor.log"
