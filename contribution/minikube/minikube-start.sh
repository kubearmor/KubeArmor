#!/bin/bash

# start minikube with a specific image
minikube start --iso-url https://accuknox.kr/minikube/minikube.iso

# download kernel-headers.tar.lz4
minikube ssh -- "curl -Lo /tmp/kernel-headers-linux-4.19.94.tar.lz4 https://accuknox.kr/minikube/kernel-headers-linux-4.19.94.tar.lz4"

# install kernel header
minikube ssh -- "sudo mkdir -p /lib/modules/4.19.94/build"
minikube ssh -- "lz4 -dc --no-sparse /tmp/kernel-headers-linux-4.19.94.tar.lz4 | sudo tar -C /lib/modules/4.19.94/build -xvf -"

# remove kernel-headers.tar.lz4
minikube ssh -- "rm /tmp/kernel-headers-linux-4.19.94.tar.lz4"
