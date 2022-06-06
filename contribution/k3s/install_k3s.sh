#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# create a single-node K3s cluster
if [ -x "$(command -v docker)" ]; then # docker
    CGROUP_SYSTEMD=$(docker info 2> /dev/null | grep -i cgroup | grep systemd | wc -l)
    if [ $CGROUP_SYSTEMD == 1 ]; then
        curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --docker --kubelet-arg cgroup-driver=systemd" sh -
        [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
    else # cgroupfs
        curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --docker" sh -
        [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
    fi
else # containerd
    curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik" sh -
    [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
fi

if [[ $(hostname) = kubearmor-dev* ]]; then
    mkdir -p /home/vagrant/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config
    sudo chown -R vagrant:vagrant /home/vagrant/.kube
    echo "export KUBECONFIG=/home/vagrant/.kube/config" | tee -a /home/vagrant/.bashrc
else
    KUBEDIR=$HOME/.kube
    KUBECONFIG=$KUBEDIR/config
    [[ ! -d $KUBEDIR ]] && mkdir $KUBEDIR
    if [ -f $KUBECONFIG ]; then
        echo "Found $KUBECONFIG already in place ... backing it up to $KUBECONFIG.backup"
        cp $KUBECONFIG $KUBECONFIG.backup
    fi
    sudo cp /etc/rancher/k3s/k3s.yaml $KUBECONFIG
    sudo chown $USER:$USER $KUBECONFIG
    echo "export KUBECONFIG=$KUBECONFIG" | tee -a ~/.bashrc
fi

echo "wait for initialization"
sleep 15

for (( ; ; ))
do
    status=$(/usr/local/bin/kubectl get pods -A -o jsonpath={.items[*].status.phase})
    [[ $(echo $status | grep -v Running | wc -l) -eq 0 ]] && break
    echo "wait for initialization"
    sleep 1
done

/usr/local/bin/kubectl get pods -A
