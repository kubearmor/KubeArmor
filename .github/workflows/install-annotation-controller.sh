#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# install cmctl
OS=$(go env GOOS); ARCH=$(go env GOARCH); curl -sSL -o cmctl.tar.gz https://github.com/cert-manager/cert-manager/releases/download/v1.7.2/cmctl-$OS-$ARCH.tar.gz
tar xzf cmctl.tar.gz
sudo mv cmctl /usr/local/bin

# install annotation controller
kubectl apply -f deployments/annotations/cert-manager.yaml
kubectl wait pods --for=condition=ready -n cert-manager -l app.kubernetes.io/instance=cert-manager
cmctl check api --wait 300s
kubectl apply -f deployments/annotations/kubearmor-annotation-manager.yaml
kubectl wait pods --for=condition=ready -n kube-system -l kubearmor-app=kubearmor-annotation-manager
