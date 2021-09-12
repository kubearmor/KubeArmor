#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

MAJOR=$(uname -r | awk -F'.' '{print $1}')
MINOR=$(uname -r | awk -F'.' '{print $2}')

echo "[INFO] Check Kernel Version (>= 4.15)"

if [ $MAJOR -le 3 ]; then
    echo "[FAIL] $(uname -r) is installed"
    exit 1
elif [ $MAJOR -eq 4 ]; then
    if [ $MINOR -lt 15 ]; then
        echo "[FAIL] $(uname -r) is installed"
        exit 1
    fi
fi

echo "[PASS] $(uname -r) is installed"
exit 0
