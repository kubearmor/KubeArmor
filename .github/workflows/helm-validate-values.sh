#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

envs=("docker" "crio" "k3s" "microk8s" "minikube" "GKE" "BottleRocket" "EKS" "generic")

echo "Testing environment specific helm templates..."
for env in ${envs[@]}; do
	echo "Generating templates for $env..."
	helm template kubearmor ./deployments/helm/KubeArmor --set environment.name=$env > $env.yml
	if [[ "$?" -eq 1 ]]
	then
		echo "Failed to generate template for $env!"
		exit 1
	fi
	rm -rf $env.yml
done

echo "Validated environment specific templates!"
