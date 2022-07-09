#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# make a temp build directory
sudo rm -rf /tmp/build
mkdir -p /tmp/build
cd /tmp/build

# install dependencies and llvm--toolchain
sudo dnf -y install git gcc gcc-c++ make cmake ethtool python3-pip python3-netaddr \
                    clang clang-devel llvm llvm-devel llvm-static kernel-devel \
                    zlib-devel elfutils-libelf-devel ncurses-devel libarchive

# install selinux tools
sudo dnf -y install policycoreutils-devel setools-console

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo >> /home/vagrant/.bashrc
    echo "alias lz='ls -lZ'" >> /home/vagrant/.bashrc
    echo >> /home/vagrant/.bashrc
elif [ -z "$GOPATH" ]; then
    echo >> ~/.bashrc
    echo "alias lz='ls -lZ'" >> ~/.bashrc
    echo >> ~/.bashrc
fi

# enable audit mode
sudo semanage dontaudit off

# install golang
echo "Installing golang binaries..."
goBinary=$(curl -s https://go.dev/dl/ | grep linux | head -n 1 | cut -d'"' -f4 | cut -d"/" -f3)
wget --quiet https://dl.google.com/go/$goBinary -O /tmp/build/$goBinary
sudo tar -C /usr/local -xzf /tmp/build/$goBinary

if [[ $(hostname) = kubearmor-dev* ]]; then
    mkdir -p /home/vagrant/go
    chown -R vagrant:vagrant /home/vagrant/go

    echo "export GOPATH=\$HOME/go" >> /home/vagrant/.bashrc
    echo "export GOROOT=/usr/local/go" >> /home/vagrant/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> /home/vagrant/.bashrc
    echo >> /home/vagrant/.bashrc
elif [ -z "$GOPATH" ]; then
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export GOROOT=/usr/local/go" >> ~/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> ~/.bashrc
    echo >> ~/.bashrc
fi

# download protoc
mkdir -p /tmp/build/protoc; cd /tmp/build/protoc
wget --quiet https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-linux-x86_64.zip -O /tmp/build/protoc/protoc-3.19.4-linux-x86_64.zip

# install protoc
sudo dnf -y install unzip
unzip protoc-3.19.4-linux-x86_64.zip
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
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0

# install kubebuilder
wget --quiet https://github.com/kubernetes-sigs/kubebuilder/releases/download/v3.1.0/kubebuilder_linux_amd64 -O /tmp/build/kubebuilder
chmod +x /tmp/build/kubebuilder; sudo mv /tmp/build/kubebuilder /usr/local/bin

if [[ $(hostname) = kubearmor-dev* ]]; then
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >> /home/vagrant/.bashrc
    echo >> /home/vagrant/.bashrc
elif [ -z "$GOPATH" ]; then
    echo 'export PATH=$PATH:/usr/local/kubebuilder/bin' >> ~/.bashrc
    echo >> ~/.bashrc
fi

# install kustomize
cd /tmp/build/
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"  | bash
sudo mv kustomize /usr/local/bin

# remove downloaded files
cd; sudo rm -rf /tmp/build
