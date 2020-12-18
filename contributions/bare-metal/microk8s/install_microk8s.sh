#!/bin/bash

sudo apt-get update

# install kernel-headers
sudo apt-get install -y linux-headers-$(uname -r)

# install microk8s
sudo snap install microk8s --classic

# check microk8s
sudo microk8s kubectl get nodes
sudo microk8s kubectl get services

# copy k8s config
mkdir -p $HOME/.kube
sudo microk8s kubectl config view --raw | sudo tee $HOME/.kube/config
sudo chown -R $USER: $HOME/.kube/

# download kubectl
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.18.1/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# check kubectl
kubectl cluster-info
