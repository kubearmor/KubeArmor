#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


export K8S_HOME=`dirname $(realpath "$0")`

# copy repo
sudo cp $K8S_HOME/kubernetes.repo /etc/yum.repos.d/kubernetes.repo

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
