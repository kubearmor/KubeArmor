#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# update repo
sudo apt-get update

# install apt-transport-https
sudo apt-get install -y apt-transport-https

# add the public key
sudo apt-key adv --recv-keys --keyserver keyserver.ubuntu.com 3746C208A7317B0F

# add the GPG key
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -

# add sources.list.d
sudo touch /etc/apt/sources.list.d/kubernetes.list
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list

# update repo
sudo apt-get update

# install Kubernetes
sudo apt-get install -y kubelet=1.21.3-00 kubeadm=1.21.3-00

# mount bpffs (for cilium)
echo "bpffs                                     /sys/fs/bpf     bpf     defaults          0       0" | sudo tee -a /etc/fstab

# install apparmor and audit
sudo apt-get install -y apparmor apparmor-utils auditd

# enable auditd
sudo systemctl enable auditd && sudo systemctl start auditd

# enable ip forwarding
if [ $(cat /proc/sys/net/ipv4/ip_forward) == 0 ]; then
    sudo bash -c "echo '1' > /proc/sys/net/ipv4/ip_forward"
    sudo bash -c "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf"
fi
