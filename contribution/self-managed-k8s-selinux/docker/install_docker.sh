#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

DOCKER_INSTALL=`dirname $(realpath "$0")`

# remove podman
sudo yum remove buildah skopeo podman containers-common atomic-registries docker container-tools

# remove left-over files
sudo rm -rf /etc/containers/* /var/lib/containers/* /etc/docker /etc/subuid* /etc/subgid*
cd ~ && rm -rf /.local/share/containers/

# disable selinux
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

# setup the repo
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# install docker
sudo dnf -y install docker-ce docker-ce-cli containerd.io

# configure daemon.json
sudo mkdir -p /etc/docker
cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "selinux-enabled": true
}
EOF

# run docker
sudo systemctl enable docker
sudo systemctl restart docker

# change mode
sudo chmod 666 /var/run/docker.sock

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
