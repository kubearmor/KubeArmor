#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 18.xx, 20.xx"
    exit
fi

# update repo
sudo apt-get update

# make a directory to build bcc
sudo rm -rf /tmp/build; mkdir -p /tmp/build; cd /tmp/build

# download bcc
git -C /tmp/build/ clone https://github.com/iovisor/bcc.git

# install bcc
mkdir -p /tmp/build/bcc/build; cd /tmp/build/bcc/build

# install dependencies for bcc
sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip \
                        clang-9 libllvm9 llvm-9-dev libclang-9-dev zlib1g-dev libelf-dev libedit-dev libfl-dev \
                        arping netperf iperf3
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr && make -j$(nproc) && sudo make install
if [ $? != 0 ]; then
    echo "Failed to install bcc"
    exit 1
fi

# install golang
echo "Installing golang binaries..."
goBinary=$(curl -s https://golang.org/dl/ | grep linux | head -n 1 | cut -d'"' -f4 | cut -d"/" -f3)
wget --quiet https://dl.google.com/go/$goBinary -O /tmp/build/$goBinary
sudo tar -C /usr/local -xzf /tmp/build/$goBinary

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo >> /home/vagrant/.bashrc
    echo "export GOPATH=\$HOME/go" >> /home/vagrant/.bashrc
    echo "export GOROOT=/usr/local/go" >> /home/vagrant/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> /home/vagrant/.bashrc
    echo >> /home/vagrant/.bashrc
    mkdir -p /home/vagrant/go; chown -R vagrant:vagrant /home/vagrant/go
elif [ -z "$GOPATH" ]; then
    echo >> ~/.bashrc
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export GOROOT=/usr/local/go" >> ~/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.bashrc
    echo >> ~/.bashrc
fi

# install apparmor and audit
sudo apt-get install -y apparmor apparmor-utils auditd

# enable auditd
sudo systemctl enable auditd && sudo systemctl start auditd

# install dependency on protoc
sudo apt-get install -y unzip

# download protoc
mkdir -p /tmp/build/protoc; cd /tmp/build/protoc
wget --quiet https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/protoc-3.14.0-linux-x86_64.zip -O /tmp/build/protoc/protoc-3.14.0-linux-x86_64.zip

# install protoc
unzip protoc-3.14.0-linux-x86_64.zip
sudo mv bin/protoc /usr/local/bin/
sudo chmod 755 /usr/local/bin/protoc

# apply env
if [[ $(hostname) = kubearmor-dev* ]]; then
    export GOPATH=/home/vagrant/go
    export GOROOT=/usr/local/go
    export PATH=$PATH:/usr/local/go/bin:/home/vagrant/go/bin
elif [ -z "$GOPATH" ]; then
    export GOPATH=$HOME/go
    export GOROOT=/usr/local/go
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
fi

# download protoc-gen-go
go get -u google.golang.org/grpc
go get -u github.com/golang/protobuf/protoc-gen-go

# install kubebuilder
wget --quiet https://github.com/kubernetes-sigs/kubebuilder/releases/download/v3.1.0/kubebuilder_linux_amd64 -O /tmp/build/kubebuilder
chmod +x /tmp/build/kubebuilder; sudo mv /tmp/build/kubebuilder /usr/local/bin

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo >> /home/vagrant/.bashrc
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >> /home/vagrant/.bashrc
elif [ -z "$GOPATH" ]; then
    echo >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >> ~/.bashrc
fi

# install kustomize
cd /tmp/build/
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
sudo mv kustomize /usr/local/bin

# remove downloaded files
cd; sudo rm -rf /tmp/build
