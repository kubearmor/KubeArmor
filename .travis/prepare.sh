#!/bin/bash

# install kernel-headers
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)

# # install golang 1.15.2
# sudo apt-get update
# sudo apt-get -y install gcc libsctp-dev make wget
# wget -q https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz -O /tmp/go1.15.2.linux-amd64.tar.gz
# sudo tar -xvf /tmp/go1.15.2.linux-amd64.tar.gz -C /usr/local

# install bcc and protoc
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install -y gcc make wget unzip bcc-tools libbcc-examples

# # apply env
# export GOPATH=$HOME/go
# export GOROOT=/usr/local/go
# export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# download protoc
mkdir -p /tmp/protoc; cd /tmp/protoc
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/protoc-3.14.0-linux-x86_64.zip -O /tmp/protoc/protoc-3.14.0-linux-x86_64.zip

# install protoc
unzip protoc-3.14.0-linux-x86_64.zip
sudo mv bin/protoc /usr/local/bin/

# download protoc-gen-go
go get -u google.golang.org/grpc
go get -u github.com/golang/protobuf/protoc-gen-go

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
