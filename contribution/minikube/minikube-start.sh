#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


# start minikube with a specific image
minikube start --iso-url https://accuknox.kr/minikube/minikube.iso --cpus 4 --memory 4096 --cni flannel

# download kernel-headers.tar.gz
minikube ssh -- curl -Lo /tmp/kernel-headers-linux-4.19.94.tar.gz https://accuknox.kr/minikube/kernel-headers-linux-4.19.94.tar.gz

# install kernel header
minikube ssh -- sudo mkdir -p /lib/modules/4.19.94/build
minikube ssh -- sudo tar xvfz /tmp/kernel-headers-linux-4.19.94.tar.gz -C /lib/modules/4.19.94/build

# remove kernel-headers.tar.gz
minikube ssh -- rm /tmp/kernel-headers-linux-4.19.94.tar.gz
