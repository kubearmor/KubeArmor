#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

sudo apt-get update
sudo apt-get -y install containerd

# sudo apt update -qq
# sudo apt install -qq -y containerd apt-transport-https
# sudo mkdir /etc/containerd
# containerd config default > /etc/containerd/config.toml
# sudo systemctl restart containerd
# sudo systemctl enable containerd >/dev/null 2>&1

# NULL 

# cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf
# overlay
# br_netfilter
# EOF

# sudo modprobe overlay
# sudo modprobe br_netfilter

# # Setup required sysctl params, these persist across reboots.
# cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
# net.bridge.bridge-nf-call-iptables  = 1
# net.ipv4.ip_forward                 = 1
# net.bridge.bridge-nf-call-ip6tables = 1
# EOF

# # Apply sysctl params without reboot
# sudo sysctl --system

# sudo apt-get install -y curl
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# RELEASE=$(lsb_release -cs)
# if [ "$RELEASE" == "impish" ]; then
#     RELEASE="focal"
# fi
# sudo apt-get install -y software-properties-common
# sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $RELEASE stable"

# sudo apt-get update
# sudo apt-get -y install containerd.io docker-ce-rootless-extras docker-scan-plugin
# sudo apt-get -y install libltdl7 libslirp0 pigz slirp4netns

# sudo mkdir -p /etc/containerd
# containerd config default | sudo tee /etc/containerd/config.toml

# sudo systemctl restart containerd