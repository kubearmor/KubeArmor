#!/bin/bash

# update repo
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

# disable selinux
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

# disable swap in /etc/fstab
sudo sed -i 's/\/dev\/mapper\/fedora-swap/#\/dev\/mapper\/fedora-swap/g' /etc/fstab
sudo swapoff -a && sudo sysctl -w vm.swappiness=0

# disable firewall
sudo systemctl stop firewalld
sudo systemctl disable firewalld

# install k8s
sudo dnf install -y kubelet kubectl kubeadm --disableexcludes=kubernetes
sudo systemctl enable kubelet
