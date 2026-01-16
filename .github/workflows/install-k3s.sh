#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

echo "RUNTIME="$RUNTIME

if [ "$RUNTIME" == "crio" ]; then
    status=$(systemctl is-active crio)
    if [ "$status" == "active" ]; then
        echo "CRI-O is already installed."
    else
        echo "CRI-O is not installed"
        ./contribution/self-managed-k8s/crio/install_crio.sh
    fi
fi

./contribution/k3s/install_k3s.sh
