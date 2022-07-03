#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

DOCKER_INSTALL=`dirname $(realpath "$0")`

# remove podman
sudo yum remove -y buildah skopeo podman containers-common atomic-registries docker container-tools

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
