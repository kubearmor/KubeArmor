#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# update repo
sudo apt-get update

# install apt-transport-https
sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# get kubernetes latest version
k8sversion=$(curl -Ls https://dl.k8s.io/release/stable.txt | cut -d "." -f 1,2)

# add the key for kubernetes repo
curl -fsSL https://pkgs.k8s.io/core:/stable:/$k8sversion/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# add sources.list.d
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/$k8sversion/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

# update repo
sudo apt-get update

# install kubernetes
sudo apt-get install -y kubeadm kubelet kubectl

# exclude kubernetes packages from updates
sudo apt-mark hold kubeadm kubelet kubectl

# mount bpffs (for cilium)
echo "bpffs                                     /sys/fs/bpf     bpf     defaults          0       0" | sudo tee -a /etc/fstab

# install apparmor
sudo apt-get install -y apparmor apparmor-utils

# enable ip forwarding
if [ $(cat /proc/sys/net/ipv4/ip_forward) == 0 ]; then
    sudo bash -c "echo '1' > /proc/sys/net/ipv4/ip_forward"
    sudo bash -c "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf"
fi

# disable rp_filter
sudo bash -c "echo 'net.ipv4.conf.all.rp_filter = 0' > /etc/sysctl.d/99-override_cilium_rp_filter.conf"
sudo systemctl restart systemd-sysctl
