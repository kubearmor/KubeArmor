#!/bin/bash

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 16.xx, 18.xx, 20.xx"
    exit
fi

# update repo
sudo apt-get update

case "$VERSION" in
"16."*)
    # install dependencies for bcc
    sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip \
                            clang-3.7 libllvm3.7 llvm-3.7-dev libclang-3.7-dev zlib1g-dev libelf-dev libedit-dev;;
"18."*)
    # install dependencies for bcc
    sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip \
                            clang-6.0 libllvm6.0 llvm-6.0-dev libclang-6.0-dev zlib1g-dev libelf-dev libedit-dev;;
"20.04"*)
    # install dependencies for bcc
    sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip \
                            clang-7 libllvm7 llvm-7-dev libclang-7-dev zlib1g-dev libelf-dev libedit-dev;;
"20.10"*)
    # install dependencies for bcc
    sudo apt-get -y install build-essential cmake bison flex git python3 python3-pip \
                            clang-8 libllvm8 llvm-8-dev libclang-8-dev zlib1g-dev libelf-dev libedit-dev;;
*)
    echo "Support Ubuntu 16.xx, 18.xx, 20.xx"; exit;;
esac

# make a directory to build bcc
sudo rm -rf /tmp/build; mkdir -p /tmp/build; cd /tmp/build

# download bcc
git -C /tmp/build/ clone https://github.com/iovisor/bcc.git

# install bcc
mkdir -p /tmp/build/bcc/build; cd /tmp/build/bcc/build
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr && make && sudo make install

# install golang 1.15.2
sudo apt-get update
sudo apt-get -y install gcc libsctp-dev make

wget -q https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz -O /tmp/build/go1.15.2.linux-amd64.tar.gz
sudo tar -xvf /tmp/build/go1.15.2.linux-amd64.tar.gz -C /usr/local

if [ "$(hostname)" == "kubearmor-dev" ]; then
    echo >> /home/vagrant/.bashrc
    echo "export GOPATH=\$HOME/go" >> /home/vagrant/.bashrc
    echo "export GOROOT=/usr/local/go" >> /home/vagrant/.bashrc
    echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> /home/vagrant/.bashrc
    echo >> /home/vagrant/.bashrc
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
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.14.0/protoc-3.14.0-linux-x86_64.zip -O /tmp/build/protoc/protoc-3.14.0-linux-x86_64.zip

# install protoc
unzip protoc-3.14.0-linux-x86_64.zip
sudo mv bin/protoc /usr/local/bin/

# apply env
if [ "$(hostname)" == "kubearmor-dev" ]; then
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

# remove downloaded files
cd; sudo rm -rf /tmp/build
