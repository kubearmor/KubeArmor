#!/bin/bash

# install kubeadm
sudo apt-get update
sudo apt-get install -y apt-transport-https curl
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo touch /etc/apt/sources.list.d/kubernetes.list
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# install apparmor and auditd
sudo apt-get install -y apparmor apparmor-utils auditd
sudo systemctl start apparmor; sudo systemctl start auditd

# turn off swap
sudo swapoff -a

# initialize kubernetes
sudo kubeadm init --pod-network-cidr=10.244.0.0/16 | tee -a ~/k8s_init.log

# copy k8s config
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $USER:$USER $HOME/.kube/config
export KUBECONFIG=$HOME/.kube/config
echo "export KUBECONFIG=$HOME/.kube/config" | tee -a ~/.bashrc

# install flannel
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/v0.12.0/Documentation/kube-flannel.yml

# disable master isolation
kubectl taint nodes --all node-role.kubernetes.io/master-
