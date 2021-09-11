#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

sudo kubeadm reset
sudo apt-get purge kubeadm kubectl kubelet kubernetes-cni kube*
sudo apt-get autoremove  

sudo systemctl stop kubelet
sudo systemctl stop docker

sudo rm -rf $HOME/.kube
sudo rm -rf /etc/cni/
sudo rm -rf /var/lib/cni/
sudo rm -rf /var/lib/etcd/
sudo rm -rf /var/lib/kubelet/*

sudo systemctl start docker
sudo systemctl start kubelet
