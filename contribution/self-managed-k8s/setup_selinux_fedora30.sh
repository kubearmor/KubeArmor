#!/bin/bash

export KUBEARMOR_HOME=`dirname $(realpath "$0")`/../..

# Install build dependencies

sudo dnf -y update
sudo dnf install -y bison cmake ethtool flex git iperf libstdc++-static \
  python-netaddr python-pip gcc gcc-c++ make zlib-devel \
  elfutils-libelf-devel  python-pip cmake make
sudo dnf install -y luajit luajit-devel 
sudo dnf install -y \
  http://repo.iovisor.org/yum/extra/mageia/cauldron/x86_64/netperf-2.7.0-1.mga6.x86_64.rpm
sudo pip install pyroute2

# Install binary clang

sudo dnf install -y clang clang-devel llvm llvm-devel llvm-static ncurses-devel

# Install and compile BCC

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cd

# Install go

wget https://dl.google.com/go/go1.15.3.linux-amd64.tar.gz
tar -xvf go1.15.3.linux-amd64.tar.gz
sudo mv go /usr/local
echo "export GOPATH=$HOME/go" >> ~/.bashrc
echo "export GOROOT=/usr/local/go" >> ~/.bashrc
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
source ~/.bashrc

# Copy cil templates

sudo cp -r $KUBEARMOR_HOME/KubeArmor/templates /usr/share/


