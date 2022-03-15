#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

docker rm -f `docker ps -aq` 2> /dev/null
docker rmi -f `docker images -aq` 2> /dev/null
docker volume rm -f `docker volume ls -q` 2> /dev/null
docker network prune -f

sudo systemctl stop docker

sudo umount /var/lib/docker/volumes 2> /dev/null
sudo rm -rf /var/lib/docker

sudo systemctl start docker

# Local docker registry
if [ -z "${SKIP_LOCAL_REGISTRY}" ];
then
docker rm --force registry || true 
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