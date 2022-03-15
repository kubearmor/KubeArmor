#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# download the latest minikube package
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb

# install minikube
sudo dpkg -i minikube_latest_amd64.deb

# remove the latest minikube package
rm minikube_latest_amd64.deb

# download the latest kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"

# install kubectl
sudo mv kubectl /usr/bin
sudo chmod 755 /usr/bin/kubectl

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
