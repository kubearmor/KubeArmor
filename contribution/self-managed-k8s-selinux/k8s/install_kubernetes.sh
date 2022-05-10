#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# disable selinux
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

# disable swap in /etc/fstab
sudo sed -e '/swap/ s/^#*/#/' -i /etc/fstab
sudo swapoff -a && sudo sysctl -w vm.swappiness=0

# disable firewall
sudo systemctl stop firewalld
sudo systemctl disable firewalld

# update iptables settings
echo "net.bridge.bridge-nf-call-ip6tables = 1" | sudo tee /etc/sysctl.d/k8s.conf
echo "net.bridge.bridge-nf-call-iptables = 1" | sudo tee -a /etc/sysctl.d/k8s.conf
sudo sysctl --system

# configure k8s repo
cat <<EOF > kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
sudo mv kubernetes.repo /etc/yum.repos.d/

# install kubernetes
if [ "$RUNTIME" == "containerd" ]; then
    sudo dnf install -y kubeadm kubelet kubectl iproute-tc
else # docker
    sudo dnf install -y kubeadm-1.23.0 kubelet-1.23.0 kubectl-1.23.0 iproute-tc
fi
sudo systemctl enable kubelet

# disable rp_filter
echo "net.ipv4.conf.all.rp_filter = 0" | sudo tee /etc/sysctl.d/override_cilium_rp_filter.conf
sudo sysctl --system
