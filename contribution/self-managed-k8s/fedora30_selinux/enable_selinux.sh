#!/bin/bash

# before enabling selinux in k8s, you should install docker, k8s first
sudo sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config
sudo setenforce 1
sudo setsebool container_manage_cgroup 1

# add { "selinux-enabled": true } to /etc/docker/daemon.json
sudo echo "{ \"selinux-enabled\": true }" >> /etc/docker/daemon.json

sudo systemctl daemon-reload && sudo systemctl restart docker
sudo chmod 666 /var/run/docker.sock
