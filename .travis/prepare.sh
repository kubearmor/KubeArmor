#!/bin/bash

# install kernel-headers
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)

# install bcc
# sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
# echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
# sudo apt-get update
# sudo apt-get install -y bcc-tools libbcc-examples

# install microk8s
sudo snap install microk8s --classic

# check microk8s
# sudo microk8s kubectl get nodes
# sudo microk8s kubectl get services

# copy k8s config
mkdir -p $HOME/.kube
sudo microk8s kubectl config view --raw | sudo tee $HOME/.kube/config
sudo chown -R travis: $HOME/.kube/

# download kubectl
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.18.1/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# check kubectl
# kubectl cluster-info
