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

# Local docker registry
if [ -z "${SKIP_LOCAL_REGISTRY}" ];
then
echo "Installing local registry"
docker run -d -p 0.0.0.0:5000:5000 --restart=always --name registry registry:2
REGIP=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
sudo cat <<EOF > daemon.json
{
"insecure-registries" : ["$REGIP:5000"]
}
EOF
sudo cp daemon.json /etc/docker/daemon.json
sudo rm daemon.json
sudo cat /etc/docker/daemon.json
sudo systemctl restart docker.service
else
	echo "Skipping local registry"
fi

# Install cert manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
