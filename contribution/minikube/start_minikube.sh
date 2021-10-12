#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# Refer to https://minikube.sigs.k8s.io/docs/tutorials/ebpf_tools_in_minikube

# start minikube with a specific image
minikube start --iso-url https://storage.googleapis.com/minikube-performance/minikube.iso --cpus 4 --memory 4096 --cni flannel

# download kernel-headers.tar.gz
minikube ssh -- curl -Lo /tmp/kernel-headers-linux-4.19.94.tar.lz4 https://storage.googleapis.com/minikube-kernel-headers/kernel-headers-linux-4.19.94.tar.lz4

# install kernel header
minikube ssh -- sudo mkdir -p /lib/modules/4.19.94/build
minikube ssh -- sudo tar -I lz4 -C /lib/modules/4.19.94/build -xvf /tmp/kernel-headers-linux-4.19.94.tar.lz4

# remove kernel-headers.tar.gz
minikube ssh -- rm /tmp/kernel-headers-linux-4.19.94.tar.lz4
