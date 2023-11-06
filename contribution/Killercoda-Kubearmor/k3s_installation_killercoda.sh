#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of KubeArmor

if [ "$RUNTIME" == "" ]; then
    if [ -S /var/run/docker.sock ]; then
        RUNTIME="docker"
    elif [ -S /var/run/crio/crio.sock ]; then
        RUNTIME="crio"
    else
        # Default runtime
        RUNTIME="containerd"
    fi
fi

# Create a single-node K3s cluster based on the chosen runtime
if [ "$RUNTIME" == "docker" ]; then
    CGROUP_SYSTEMD=$(docker info 2> /dev/null | grep -i cgroup | grep systemd | wc -l)
    if [ $CGROUP_SYSTEMD == 1 ]; then
        curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.23.9+k3s1" K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --docker --kubelet-arg cgroup-driver=systemd" sh - 2>/dev/null
        [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
    else
        curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="v1.23.9+k3s1" K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --docker" sh - 2>/dev/null
        [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
    fi
elif [ "$RUNTIME" == "crio" ]; then
  curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --container-runtime-endpoint unix:///var/run/crio/crio.sock --kubelet-arg cgroup-driver=systemd" sh - 2>/dev/null
  [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
else
  curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik" sh - 2>/dev/null
  [[ $? != 0 ]] && echo "Failed to install k3s" && exit 1
fi

if [[ $(hostname) = kubearmor-dev* ]]; then
    mkdir -p /home/vagrant/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config
    echo "export KUBECONFIG=/home/vagrant/.kube/config" | tee -a /home/vagrant/.bashrc
    PATH=$PATH:/bin:/usr/bin:/usr/local/bin
else
    KUBEDIR=$HOME/.kube
    KUBECONFIG=$KUBEDIR/config
    [[ ! -d $KUBEDIR ]] && mkdir $KUBEDIR
    if [ -f $KUBECONFIG ]; then
        echo "Found $KUBECONFIG already in place ... backing it up to $KUBECONFIG.backup"
        cp $KUBECONFIG $KUBECONFIG.backup
    fi
    sudo cp /etc/rancher/k3s/k3s.yaml $KUBECONFIG
    echo "export KUBECONFIG=$KUBECONFIG" | tee -a ~/.bashrc
fi

sleep 30
echo "Waiting for all pods in kube-system to be in the 'Running' state"
kubectl wait --for=condition=Ready pod --all --namespace=kube-system --timeout=300s
kubectl get pods -A

echo "All pods in kube-system are now in the 'Running' state"
