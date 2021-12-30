#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# Refer to https://minikube.sigs.k8s.io/docs/tutorials/ebpf_tools_in_minikube

# download minikube iso
wget -O minikube.iso https://github.com/kubearmor/kastore/blob/main/iso/minikube/minikube.iso?raw=true

# start minikube with a specific image

minikube start --iso-url=file://$(pwd)/minikube.iso --cpus 4 --memory 4096 --cni flannel
