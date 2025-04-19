#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

# Check for supported Ubuntu versions
if [[ "$NAME" != "Ubuntu" || ! "$VERSION_ID" =~ 20.04|22.04 ]]; then
    echo "Unsupported OS version. This script supports Ubuntu 20.04 and 22.04."
    exit 1
fi


OS="x${NAME}_${VERSION_ID}"

# install cri-o corresponding to the latest k3s version

VERSION=$(curl -w '%{url_effective}' -L -s -S https://update.k3s.io/v1-release/channels/stable -o /dev/null | sed -e 's|.*/||' | cut -d '.' -f1,2)
echo "Installing CRI-O version $VERSION"


curl -fsSL https://pkgs.k8s.io/addons:/cri-o://stable:/$VERSION/deb/Release.key |
    sudo gpg --dearmor -o /etc/apt/keyrings/cri-o-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/cri-o-apt-keyring.gpg] https://pkgs.k8s.io/addons:/cri-o:/stable:/$VERSION/deb/ /" |
    sudo tee /etc/apt/sources.list.d/cri-o.list

# install
sudo apt-get update
sudo apt-get install -y cri-o
sudo dpkg -i --force-overwrite /var/cache/apt/archives/cri-o_*.deb


sudo systemctl daemon-reload
sudo systemctl start crio.service

# Verify installation
if systemctl is-active --quiet crio.service; then
    echo "CRI-O installation successful and service is running."
else
    echo "CRI-O installation failed or service did not start. Check logs using 'journalctl -u crio.service'."
    exit 1
fi