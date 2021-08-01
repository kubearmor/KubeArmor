#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


# setup the repo
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager \
    --add-repo \
    https://download.docker.com/linux/fedora/docker-ce.repo

# install docker
sudo dnf -y install docker-ce-3:19.03.9-3.fc30 containerd.io

# run docker
sudo systemctl enable docker
sudo systemctl start docker

# change mode
sudo chmod 666 /var/run/docker.sock
