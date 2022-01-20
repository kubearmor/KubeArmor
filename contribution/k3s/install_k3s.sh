#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# create a single-node K3s cluster
curl -sfL https://get.k3s.io | K3S_KUBECONFIG_MODE="644" INSTALL_K3S_EXEC="--disable=traefik --docker" sh -
[[ $? != 0 ]] && echo "Failed to install k3s" && exit 1

KUBEDIR=$HOME/.kube
KUBECONFIG=$KUBEDIR/config

[[ ! -d $KUBEDIR ]] && mkdir $HOME/.kube/
if [ -f $KUBECONFIG ]; then
	KUBECONFIGBKP=$KUBEDIR/config.backup
	echo "Found $KUBECONFIG already in place ... backing it up to $KUBECONFIGBKP"
	cp $KUBECONFIG $KUBECONFIGBKP
fi

cp /etc/rancher/k3s/k3s.yaml $KUBEDIR/config 

echo "wait for initialization"
sleep 15

for (( ; ; ))
do
	status=$(kubectl get pods -A -o jsonpath={.items[*].status.phase})
	[[ $(echo $status | grep -v Running | wc -l) -eq 0 ]] && break
	echo "wait for initialization"
	sleep 1
done

kubectl get pods -A
