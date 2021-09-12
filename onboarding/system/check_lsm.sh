#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

echo "[INFO] Check LSMs"

sudo ls /sys/kernel/security &> /dev/null
if [ $? != 0 ]; then
    echo "[FAIL] Failed to access /sys/kernel/security"
    exit 1
fi

LSM=0

APPARMOR=$(sudo cat /sys/kernel/security/lsm | grep apparmor | wc -l)
if [ $APPARMOR == 1 ]; then
    APPARMOR_DIRS=0

    if [ ! -d "/etc/apparmor.d/abstractions" ]; then
        echo "[FAIL] Failed to find /etc/apparmor.d/abstractions"
    else
        APPARMOR_DIRS=`expr $APPARMOR_DIRS + 1`
    fi

    if [ ! -d "/etc/apparmor.d/tunables" ]; then
        echo "[FAIL] Failed to find /etc/apparmor.d/tunables"
    else
        APPARMOR_DIRS=`expr $APPARMOR_DIRS + 1`
    fi

    if [ $APPARMOR_DIRS == 2 ]; then
        echo "[PASS] AppArmor is enabled"
        LSM=1
    fi
fi

SELINUX=$(sudo cat /sys/kernel/security/lsm | grep selinux | wc -l)
if [ $SELINUX == 1 ]; then
    echo "[PASS] SELinux is enabled"
    LSM=1
fi

if [ $LSM != 1 ]; then
    echo "[FAIL] No LSM is detected"
    exit 1
fi

exit 0
