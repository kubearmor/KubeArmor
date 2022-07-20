#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# before enabling selinux in k8s, you should install docker, k8s first
sudo sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config
sudo setenforce 1

if [ -f /var/run/docker.sock ]; then
    # change contexts
    sudo setsebool container_manage_cgroup 1
    sudo chcon -R -t svirt_sandbox_file_t /var/lib/etcd
    sudo chcon -R -t svirt_sandbox_file_t /etc/kubernetes/
fi
