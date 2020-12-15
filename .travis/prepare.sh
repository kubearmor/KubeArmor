#!/bin/bash

sudo apt-get update

# install kernel-headers
sudo apt-get install -y linux-headers-$(uname -r)

# install dependencies
sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip python3-distutils \
                        clang-6.0 libllvm6.0 llvm-6.0-dev libclang-6.0-dev zlib1g-dev libelf-dev libedit-dev bc \
                        arping netperf iperf3

# make a directory to build bcc
sudo rm -rf /tmp/build; mkdir -p /tmp/build; cd /tmp/build

# download bcc
git -C /tmp/build/ clone https://github.com/iovisor/bcc.git

# install bcc
mkdir -p /tmp/build/bcc/build; cd /tmp/build/bcc/build
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install

# install microk8s
sudo snap install microk8s --classic

# check microk8s
sudo microk8s kubectl get nodes
sudo microk8s kubectl get services

# copy k8s config
mkdir $HOME/.kube
sudo microk8s kubectl config view --raw | sudo tee $HOME/.kube/config
sudo chown -R travis: $HOME/.kube/

# download kubectl
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.18.1/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# check kubectl
kubectl cluster-info
