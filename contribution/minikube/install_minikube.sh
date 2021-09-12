#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# download the latest minikube package
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb

# install minikube
sudo dpkg -i minikube_latest_amd64.deb

# remove the latest minikube package
rm minikube_latest_amd64.deb

# download the latest kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# install kubectl
sudo mv kubectl /usr/bin
sudo chmod 755 /usr/bin/kubectl
