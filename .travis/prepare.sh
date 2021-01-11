#!/bin/bash

# install kernel-headers
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)

# install microk8s
sudo snap install microk8s --classic

# copy k8s config
mkdir -p $HOME/.kube
sudo microk8s kubectl config view --raw | sudo tee $HOME/.kube/config
sudo chown -R travis: $HOME/.kube/

# download kubectl
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.18.1/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
