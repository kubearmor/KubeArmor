#!/bin/bash

sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)

sudo snap install microk8s --classic

sudo microk8s kubectl get nodes
sudo microk8s kubectl get services

sudo microk8s kubectl config view --raw > $HOME/.kube/config
