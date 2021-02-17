#!/bin/bash

LSM=0

sudo ls /sys/kernel/security
if [ $? != 0 ]; then
    echo "[FAIL] Failed to access /sys/kernel/security"
    exit 1
fi
echo $(sudo cat /sys/kernel/security/lsm)

APPARMOR=$(sudo cat /sys/kernel/security/lsm | grep apparmor | wc -l)
if [ $APPARMOR == 1 ]; then
    echo "[PASS] AppArmor is enabled"
    LSM=1
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
