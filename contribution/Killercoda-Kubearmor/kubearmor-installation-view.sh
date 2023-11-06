#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of KubeArmor

namespace="kubearmor"

echo "Waiting for all pods in namespace '$namespace' to be in the 'Running' state"

kubectl wait --for=condition=ready --timeout=5m -n kubearmor pod -l kubearmor-app=kubearmor-operator
kubectl get po -n $namespace
kubectl wait -n kubearmor --timeout=5m --for=jsonpath='{.status.phase}'=Running kubearmorconfigs/kubearmor-default
kubectl wait --timeout=5m --for=condition=ready pod -l kubearmor-app,kubearmor-app!=kubearmor-snitch -n kubearmor
kubectl wait --timeout=5m --for=condition=ready pod -l kubearmor-app=kubearmor,kubearmor-app!=kubearmor-snitch -n kubearmor

echo "All pods in namespace '$namespace' are now in the 'Running' state"

kubectl get po -n $namespace
