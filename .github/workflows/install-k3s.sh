#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

echo "RUNTIME="$RUNTIME

if [ "$RUNTIME" == "crio" ]; then
    ./contribution/self-managed-k8s/crio/install_crio.sh
fi

./contribution/k3s/install_k3s.sh
