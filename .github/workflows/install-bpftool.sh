#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
set -euo pipefail

BPFTOOL_VERSION="v7.3.0"
arch=$(uname -m)
if [[ "$arch" == "aarch64" ]]; then
  arch=arm64
elif [[ "$arch" == "x86_64" ]]; then
  arch=amd64
fi

curl -LO "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-${arch}.tar.gz"
sudo tar -xzf "bpftool-${BPFTOOL_VERSION}-${arch}.tar.gz" -C /usr/local/bin
sudo chmod +x /usr/local/bin/bpftool
rm "bpftool-${BPFTOOL_VERSION}-${arch}.tar.gz"
bpftool version