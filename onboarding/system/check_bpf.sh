#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

echo "[INFO] Check BPF capabilities"

grep 'CONFIG_BPF=y' /boot/config-$(uname -r) &> /dev/null
if [ $? != 0 ]; then
    echo "[FAIL] CONFIG_BPF is not enabled"
    exit 1
else
    echo "[PASS] CONFIG_BPF is enabled"
fi

grep 'CONFIG_BPF_SYSCALL=y' /boot/config-$(uname -r) &> /dev/null
if [ $? != 0 ]; then
    echo "[FAIL] CONFIG_BPF_SYSCALL is not enabled"
    exit 1
else
    echo "[PASS] CONFIG_BPF_SYSCALL is enabled"
fi

grep 'CONFIG_BPF_EVENTS=y' /boot/config-$(uname -r) &> /dev/null
if [ $? != 0 ]; then
    echo "[FAIL] CONFIG_BPF_EVENTS is not enabled"
    exit 1
else
    echo "[PASS] CONFIG_BPF_EVENTS is enabled"
    exit 0
fi
