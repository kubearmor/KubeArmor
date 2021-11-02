#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# create a single-node K3s cluster
curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--flannel-backend=none --cluster-cidr=192.168.0.0/16 --disable-network-policy --disable=traefik" sh -

# install Calico-Operator
kubectl create -f https://docs.projectcalico.org/manifests/tigera-operator.yaml

# install Calico-Manifest
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
