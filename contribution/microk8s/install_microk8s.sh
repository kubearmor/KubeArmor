#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# update repo
sudo apt-get update

# install kernel-headers
sudo apt-get install -y linux-headers-$(uname -r)

# install microk8s
sudo snap install microk8s --classic

# check microk8s
sudo microk8s kubectl get nodes
sudo microk8s kubectl get services

# copy k8s config
mkdir -p $HOME/.kube
sudo microk8s kubectl config view --raw | sudo tee $HOME/.kube/config
sudo chown -R $USER: $HOME/.kube/

# download kubectl
curl -Lo kubectl https://storage.googleapis.com/kubernetes-release/release/v1.18.1/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# check kubectl
kubectl cluster-info

# install apparmor and audit
sudo apt-get install -y apparmor apparmor-utils auditd

# enable auditd
sudo systemctl enable auditd && sudo systemctl start auditd

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
