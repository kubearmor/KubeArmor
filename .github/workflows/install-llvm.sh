#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

. /etc/os-release

sudo apt-get -y install build-essential libelf-dev pkg-config

if [ "$VERSION_CODENAME" == "focal" ] || [ "$VERSION_CODENAME" == "bionic" ]; then
    sudo apt-get install -y clang-12 llvm-12
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-12 /usr/bin/$tool
    done
elif [ "$VERSION_CODENAME" == "jammy" ]; then
    sudo apt-get install -y clang-14 llvm-14
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-14 /usr/bin/$tool
    done
else
    sudo apt-get install -y clang-19 llvm-19
    for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
        sudo rm -f /usr/bin/$tool
        sudo ln -s /usr/bin/$tool-19 /usr/bin/$tool
    done
fi
