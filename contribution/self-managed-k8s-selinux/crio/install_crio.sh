#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

. /etc/os-release

if [ "$ID" != "centos" ]; then
    echo "Supports CentOS"
    exit
fi

OS="CentOS_${VERSION_ID}"
VERSION=1.19

if [ "$NAME" == "CentOS Stream" ]; then
	OS="${OS}_Stream"
fi

# remove podman
sudo yum remove buildah skopeo podman containers-common atomic-registries docker container-tools

# remove left-over files
sudo rm -rf /etc/containers/* /var/lib/containers/* /etc/docker /etc/subuid* /etc/subgid*
cd ~ && rm -rf /.local/share/containers/

# disable selinux
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

# setup repo
sudo curl -L -o /etc/yum.repos.d/devel:kubic:libcontainers:stable.repo https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/$OS/devel:kubic:libcontainers:stable.repo
sudo curl -L -o /etc/yum.repos.d/devel:kubic:libcontainers:stable:cri-o:$VERSION.repo https://download.opensuse.org/repositories/devel:kubic:libcontainers:stable:cri-o:$VERSION/$OS/devel:kubic:libcontainers:stable:cri-o:$VERSION.repo

sudo yum install cri-o containernetworking-plugins

sudo systemctl daemon-reload
sudo systemctl start crio.service
