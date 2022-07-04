#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# set default
if [ "$CNI" == "" ]; then
    CNI=cilium
fi

# use docker as default CRI
if [ "$CRI_SOCKET" == "" ]; then
    if [ -S /var/run/docker.sock ]; then
        CRI_SOCKET=unix:///var/run/docker.sock
    elif [ -S /var/run/containerd/containerd.sock ]; then
        CRI_SOCKET=unix:///var/run/containerd/containerd.sock
    elif [ -S /var/run/crio/crio.sock ]; then
        CRI_SOCKET=unix:///var/run/crio/crio.sock
    fi
fi

# check supported CNI
if [ "$CNI" != "flannel" ] && [ "$CNI" != "weave" ] && [ "$CNI" != "calico" ] && [ "$CNI" != "cilium" ]; then
    echo "Usage: CNI={flannel|weave|calico|cilium} CRI_SOCKET=unix:///path/to/socket_file MASTER={true|false} $0"
    exit
fi

# reload env
. ~/.bashrc

# turn off swap
sudo swapoff -a

# configure selinux labels
sudo mkdir -p /var/lib/etcd/
sudo mkdir -p /etc/kubernetes/pki/
sudo chcon -R -t svirt_sandbox_file_t /var/lib/etcd
sudo chcon -R -t svirt_sandbox_file_t /etc/kubernetes/

# initialize the master node
if [ "$CNI" == "calico" ]; then
    sudo kubeadm init --cri-socket=$CRI_SOCKET --pod-network-cidr=192.168.0.0/16 | tee -a ~/k8s_init.log
else # weave, flannel, cilium
    sudo kubeadm init --cri-socket=$CRI_SOCKET --pod-network-cidr=10.244.0.0/16 | tee -a ~/k8s_init.log
fi

# make kubectl work for non-root user
if [[ $(hostname) = kubearmor-dev* ]]; then
    mkdir -p /home/vagrant/.kube
    sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
    sudo chown vagrant:vagrant /home/vagrant/.kube/config
    export KUBECONFIG=/home/vagrant/.kube/config
    echo "export KUBECONFIG=/home/vagrant/.kube/config" | tee -a /home/vagrant/.bashrc
else
    mkdir -p $HOME/.kube
    sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    sudo chown $USER:$USER $HOME/.kube/config
    export KUBECONFIG=$HOME/.kube/config
    echo "export KUBECONFIG=$HOME/.kube/config" | tee -a ~/.bashrc
    sudo cp -r $HOME/.kube/ /root/
fi

if [ "$CNI" == "flannel" ]; then
    # install a pod network (flannel)
    kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/v0.17.0/Documentation/kube-flannel.yml
elif [ "$CNI" == "weave" ]; then
    # install a pod network (weave)
    export kubever=$(kubectl version | base64 | tr -d '\n')
    kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$kubever"
elif [ "$CNI" == "calico" ]; then
    # install a pod network (calico)
    kubectl apply -f https://projectcalico.docs.tigera.io/manifests/calico.yaml
elif [ "$CNI" == "cilium" ]; then
    # install a pod network (cilium)
    curl -L --remote-name-all https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz{,.sha256sum}
    sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
    sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
    rm cilium-linux-amd64.tar.gz{,.sha256sum}
    /usr/local/bin/cilium install
fi

if [ "$MASTER" == "true" ]; then
    # disable master isolation (due to the lack of resources)
    kubectl taint nodes --all node-role.kubernetes.io/master-
fi
