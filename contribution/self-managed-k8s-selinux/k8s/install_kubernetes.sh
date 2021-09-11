#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

realpath() {
    CURR=$PWD

    cd "$(dirname "$0")"
    LINK=$(readlink "$(basename "$0")")

    while [ "$LINK" ]; do
        cd "$(dirname "$LINK")"
        LINK=$(readlink "$(basename "$1")")
    done

    REALPATH="$PWD/$(basename "$1")"
    echo "$REALPATH"

    cd $CURR
}

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
sudo dnf install -y kubelet-1.21.3-0 kubectl-1.21.3-0 kubeadm-1.21.3-0 --disableexcludes=kubernetes
sudo systemctl enable kubelet
