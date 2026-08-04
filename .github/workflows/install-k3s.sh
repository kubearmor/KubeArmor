#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

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

# Add K3s health check
echo "Waiting for K3s to become ready..."
for i in {1..60}; do
  if kubectl get nodes &>/dev/null && [ "$(kubectl get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')" == "True" ]; then
    echo "K3s cluster is ready"
    exit 0
  fi
  echo "Attempt $i/60: Waiting for K3s API server..."
  sleep 5
done

echo "ERROR: K3s failed to become ready"
sudo systemctl status k3s || true
sudo journalctl -u k3s -n 100 || true
exit 1
