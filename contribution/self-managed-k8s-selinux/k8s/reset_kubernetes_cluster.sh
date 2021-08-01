#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


sudo kubeadm reset
sudo dnf -y remove kubeadm kubectl kubelet 

sudo systemctl stop kubelet
sudo systemctl stop docker

sudo rm -rf $HOME/.kube
sudo rm -rf /etc/cni/
sudo rm -rf /var/lib/cni/
sudo rm -rf /var/lib/etcd/
sudo rm -rf /var/lib/kubelet/*

sudo systemctl start docker
sudo systemctl start kubelet
