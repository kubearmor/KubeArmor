#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$NAME" != "Ubuntu" ]; then
    echo "Support Ubuntu 18.xx, 20.xx"
    exit
fi

OS="x${NAME}_${VERSION_ID}"

# install cri-o corresponding to the latest k3s version
VERSION=$(curl -w '%{url_effective}' -L -s -S https://update.k3s.io/v1-release/channels/stable -o /dev/null | sed -e 's|.*/v||' | cut -d '.' -f1,2)
echo "Installing CRI-O version $VERSION"

# get signing keys
echo "deb [signed-by=/usr/share/keyrings/libcontainers-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list
echo "deb [signed-by=/usr/share/keyrings/libcontainers-crio-archive-keyring.gpg] https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/ /" | sudo tee /etc/apt/sources.list.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.list

# add repositories
sudo mkdir -p /usr/share/keyrings
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/Release.key | sudo gpg --yes --dearmor -o /usr/share/keyrings/libcontainers-archive-keyring.gpg
curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable:/cri-o:/$VERSION/$OS/Release.key | sudo gpg --yes --dearmor -o /usr/share/keyrings/libcontainers-crio-archive-keyring.gpg

# install
sudo apt-get update
sudo apt-get install -y cri-o cri-o-runc
sudo systemctl start crio
sudo systemctl enable crio
sudo systemctl status crio
#By default, there is no CNI plugin installed and configured for CRIO
sudo apt install containernetworking-plugins -y

crio_config_file="/etc/crio/crio.conf"
# Uncomment network_dir and plugin_dirs sections
sed -i '/^[[:space:]]*#[[:space:]]*network_dir =/s/^[[:space:]]*#//' "$crio_config_file"
sed -i '/^# *plugin_dirs = \[/,/\]$/ s/^# *//' "$crio_config_file"
sed -i '/\/opt\/cni\/bin\// a "/usr/lib/cni/",' "$crio_onfig_file"

sudo systemctl restart crio

# this option is not supported in ubuntu 18.04
if [ "$VERSION_ID" == "18.04" ]; then
    sudo sed -i 's/,metacopy=on//g' /etc/containers/storage.conf
fi

sudo systemctl daemon-reload
sudo systemctl start crio.service
