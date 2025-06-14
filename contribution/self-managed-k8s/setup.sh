#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 18.xx, 20.xx"
    exit
fi

# make a temp build directory
sudo rm -rf /tmp/build
mkdir -p /tmp/build
cd /tmp/build

# update repo
sudo apt-get update

export DEBIAN_FRONTEND=noninteractive
echo 'debconf debconf/frontend select Noninteractive' | sudo debconf-set-selections

# install dependencies and llvm--toolchain
sudo apt-get -y install build-essential libelf-dev pkg-config net-tools linux-headers-$(uname -r) linux-tools-$(uname -r)
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
if [ "$VERSION_CODENAME" == "focal" ] || [ "$VERSION_CODENAME" == "bionic" ]; then
    sudo ./llvm.sh 12
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-12 /usr/bin/$tool
    done
elif [ "$VERSION_CODENAME" == "jammy" ]; then
    sudo ./llvm.sh 14
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-14 /usr/bin/$tool
    done
else # VERSION_CODENAME == noble
    sudo ./llvm.sh 19
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-19 /usr/bin/$tool
    done
fi

# install libbpf-dev
if [ "$VERSION_CODENAME" == "jammy" ]|| [ "$VERSION_CODENAME" == "noble" ]; then
    sudo apt-get -y install libbpf-dev
fi

# install golang
echo "Installing golang binaries..."
goBinary=$(curl -s https://go.dev/dl/ | grep linux | head -n 1 | cut -d'"' -f4 | cut -d"/" -f3)
wget --quiet https://dl.google.com/go/$goBinary -O /tmp/build/$goBinary
sudo tar -C /usr/local -xzf /tmp/build/$goBinary

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo >>/home/vagrant/.bashrc
    echo "export GOPATH=\$HOME/go" >>/home/vagrant/.bashrc
    echo "export GOROOT=/usr/local/go" >>/home/vagrant/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >>/home/vagrant/.bashrc
    echo >>/home/vagrant/.bashrc
    mkdir -p /home/vagrant/go
    chown -R vagrant:vagrant /home/vagrant/go
elif [ -z "$GOPATH" ]; then
    echo >>~/.bashrc
    echo "export GOPATH=\$HOME/go" >>~/.bashrc
    echo "export GOROOT=/usr/local/go" >>~/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >>~/.bashrc
    echo >>~/.bashrc
fi

# install apparmor and audit
sudo apt-get install -y apparmor apparmor-utils auditd

# enable auditd
sudo systemctl enable auditd && sudo systemctl start auditd

sudo apt-get install -y unzip protobuf-compiler

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
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# install kubebuilder
wget --quiet https://github.com/kubernetes-sigs/kubebuilder/releases/download/v3.1.0/kubebuilder_linux_amd64 -O /tmp/build/kubebuilder
chmod +x /tmp/build/kubebuilder
sudo mv /tmp/build/kubebuilder /usr/local/bin

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >>/home/vagrant/.bashrc
    echo >>/home/vagrant/.bashrc
elif [ -z "$GOPATH" ]; then
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >>~/.bashrc
    echo >>~/.bashrc
fi

# install kustomize
cd /tmp/build/
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
sudo mv kustomize /usr/local/bin

# remove downloaded files
cd
sudo rm -rf /tmp/build

# install bpftool from sources

cd $HOME
export arch=$(uname -m)
export bpftool_version=v7.2.0
if [[ "$arch" == "aarch64" ]]; then
  arch=arm64;
elif [[ "$arch" == "x86_64" ]]; then
  arch=amd64;
fi
curl -LO https://github.com/libbpf/bpftool/releases/download/$bpftool_version/bpftool-$bpftool_version-$arch.tar.gz && \
    sudo tar -xzf bpftool-$bpftool_version-$arch.tar.gz -C /usr/local/bin && \
    sudo chmod +x /usr/local/bin/bpftool
