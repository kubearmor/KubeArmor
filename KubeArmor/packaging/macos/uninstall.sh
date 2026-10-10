#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -euo pipefail

PLIST_NAME="io.kubearmor.daemon.plist"
DAEMON_PLIST="/Library/LaunchDaemons/${PLIST_NAME}"
NEWSYSLOG_CONF="/etc/newsyslog.d/io.kubearmor.conf"
BIN_DIR="/opt/kubearmor"
LOG_DIR="/var/log/kubearmor"
PURGE=false

for arg in "$@"; do
    case "${arg}" in
        --purge)
            PURGE=true
            ;;
        --help|-h)
            echo "Usage: sudo ./uninstall.sh [--purge]"
            echo "  --purge: Also remove log files in ${LOG_DIR} and binaries in ${BIN_DIR}"
            exit 0
            ;;
    esac
done

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This uninstallation script must be run as root (e.g. using sudo)." >&2
    exit 1
fi

echo "=== Uninstalling KubeArmor from macOS ==="

# 1. Stop and unload daemon from launchctl
if [ -f "${DAEMON_PLIST}" ] || launchctl list io.kubearmor.daemon >/dev/null 2>&1; then
    echo "Stopping and unloading io.kubearmor.daemon from launchctl..."
    launchctl bootout system/io.kubearmor.daemon 2>/dev/null || launchctl unload "${DAEMON_PLIST}" 2>/dev/null || true
fi

# 2. Remove LaunchDaemon plist
if [ -f "${DAEMON_PLIST}" ]; then
    echo "Removing LaunchDaemon plist: ${DAEMON_PLIST}..."
    rm -f "${DAEMON_PLIST}"
fi

# 3. Remove newsyslog configuration
if [ -f "${NEWSYSLOG_CONF}" ]; then
    echo "Removing newsyslog rotation config: ${NEWSYSLOG_CONF}..."
    rm -f "${NEWSYSLOG_CONF}"
fi

# 4. Optional purge of binaries and logs
if [ "${PURGE}" = true ]; then
    echo "Purging binaries from ${BIN_DIR}..."
    rm -rf "${BIN_DIR}"
    echo "Purging log files from ${LOG_DIR}..."
    rm -rf "${LOG_DIR}"
else
    echo "Note: Log files in ${LOG_DIR} and binaries in ${BIN_DIR} were preserved."
    echo "To remove them, re-run with: sudo ./uninstall.sh --purge"
fi

echo "=== KubeArmor macOS Uninstallation Complete ==="
