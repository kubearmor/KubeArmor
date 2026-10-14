#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

set -uo pipefail

if ! command -v helm >/dev/null 2>&1; then
	echo "helm is not installed or not on PATH!"
	exit 1
fi

envs=("docker" "crio" "k3s" "microk8s" "minikube" "GKE" "BottleRocket" "EKS" "generic")

echo "Testing environment specific helm templates..."
for env in "${envs[@]}"; do
	echo "Generating templates for $env..."
	if ! helm template kubearmor ./deployments/helm/KubeArmor --set environment.name="$env" > "$env.yml"
	then
		echo "Failed to generate template for $env!"
		rm -f "$env.yml"
		exit 1
	fi
	rm -f "$env.yml"
done

echo "Validated environment specific templates!"
