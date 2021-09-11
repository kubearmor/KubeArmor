#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

if [ ! -z $1 ] && [ "$1" == "help" ]; then
    echo "Usage: $0 [ flannel | weave | calico | cilium ] (master)"
    exit
fi

# reload env
. ~/.bashrc

# turn off swap
sudo swapoff -a

# activate br_netfilter
sudo modprobe br_netfilter
sudo bash -c "echo '1' > /proc/sys/net/bridge/bridge-nf-call-iptables"
sudo bash -c "echo 'net.bridge.bridge-nf-call-iptables=1' >> /etc/sysctl.conf"

if [ ! -z $1 ] && [ "$1" == "weave" ]; then
    # initialize the master node (weave)
    sudo kubeadm init | tee -a ~/k8s_init.log
elif [ ! -z $1 ] && [ "$1" == "flannel" ]; then
    # initialize the master node (flannel)
    sudo kubeadm init --pod-network-cidr=10.244.0.0/16 | tee -a ~/k8s_init.log
elif [ ! -z $1 ] && [ "$1" == "calico" ]; then
    # initialize the master node (calico)
    sudo kubeadm init --pod-network-cidr=192.168.0.0/16 | tee -a ~/k8s_init.log
else
    # initialize the master node (cilium)
    sudo kubeadm init --pod-network-cidr=192.168.0.0/16 | tee -a ~/k8s_init.log
fi

# make kubectl work for non-root user
if [[ $(hostname) = kubearmor-dev* ]]; then
    mkdir -p /home/vagrant/.kube
    sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo chown -R vagrant:vagrant /home/vagrant/.kube
    export KUBECONFIG=/home/vagrant/.kube/config
    echo "export KUBECONFIG=/home/vagrant/.kube/config" | tee -a /home/vagrant/.bashrc
else
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $USER:$USER $HOME/.kube/config
    export KUBECONFIG=$HOME/.kube/config
    echo "export KUBECONFIG=$HOME/.kube/config" | tee -a ~/.bashrc
fi

if [ ! -z $1 ] && [ "$1" == "weave" ]; then
    # install a pod network (weave)
    export kubever=$(kubectl version | base64 | tr -d '\n')
    kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"
elif [ ! -z $1 ] && [ "$1" == "flannel" ]; then
    # install a pod network (flannel)
    kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/v0.13.0/Documentation/kube-flannel.yml
elif [ ! -z $1 ] && [ "$1" == "calico" ]; then
    # install a pod network (calico)
    kubectl apply -f https://docs.projectcalico.org/v3.6/manifests/calico.yaml
else
    # install a pod network (cilium)
    kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.9/install/kubernetes/quick-install.yaml
fi

if [ ! -z $2 ] && [ "$2" == "master" ]; then
    # disable master isolation (due to the lack of resources)
    kubectl taint nodes --all node-role.kubernetes.io/master-
elif [ -z $1 ]; then
    # disable master isolation (due to the lack of resources) by default
    kubectl taint nodes --all node-role.kubernetes.io/master-
fi
