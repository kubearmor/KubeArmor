#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

sudo apt-get -y install build-essential libelf-dev pkg-config
wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh

if [ "$VERSION_CODENAME" == "focal" ] || [ "$VERSION_CODENAME" == "bionic" ]; then
    sudo bash /tmp/llvm.sh 12
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-12 /usr/bin/$tool
    done
elif [ "$VERSION_CODENAME" == "jammy" ]; then
    sudo bash /tmp/llvm.sh 14
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-14 /usr/bin/$tool
    done
else # VERSION_CODENAME == noble
    sudo  bash /tmp/llvm.sh 19
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-19 /usr/bin/$tool
    done
fi

