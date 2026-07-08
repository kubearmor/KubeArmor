#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -euo pipefail

envs=("docker" "crio" "k3s" "microk8s" "minikube" "GKE" "BottleRocket" "EKS" "generic")

if ! command -v helm >/dev/null 2>&1; then
	echo "helm is required to validate environment specific templates." >&2
	exit 1
fi

echo "Testing environment specific helm templates..."
for env in "${envs[@]}"; do
	echo "Generating templates for $env..."
	output_file="${env}.yml"
	helm template kubearmor ./deployments/helm/KubeArmor --set "environment.name=$env" > "$output_file"
	rm -f "$output_file"
done

echo "Validated environment specific templates!"
