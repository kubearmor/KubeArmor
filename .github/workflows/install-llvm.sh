#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

. /etc/os-release

set -euo pipefail

sudo apt-get -y install build-essential libelf-dev pkg-config

if [ "$VERSION_CODENAME" == "focal" ] || [ "$VERSION_CODENAME" == "bionic" ]; then
    LLVM_VERSION=12
elif [ "$VERSION_CODENAME" == "jammy" ]; then
    LLVM_VERSION=14
else
    LLVM_VERSION=19
fi

sudo apt-get install -y "clang-${LLVM_VERSION}" "llvm-${LLVM_VERSION}"

for tool in "clang" "llc" "llvm-strip" "opt" "llvm-dis"; do
    if [ -x "/usr/bin/${tool}-${LLVM_VERSION}" ]; then
        tool_path="/usr/bin/${tool}-${LLVM_VERSION}"
    elif [ -x "/usr/lib/llvm-${LLVM_VERSION}/bin/${tool}" ]; then
        tool_path="/usr/lib/llvm-${LLVM_VERSION}/bin/${tool}"
    else
        echo "Could not find ${tool} for LLVM ${LLVM_VERSION}" >&2
        exit 1
    fi

    sudo rm -f "/usr/bin/${tool}"
    sudo ln -s "${tool_path}" "/usr/bin/${tool}"
done
